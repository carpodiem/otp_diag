from __future__ import division
from builtins import map
from builtins import object
import os
import subprocess
import sys
import tarfile
import logging
import datetime
import time
import optparse
import fnmatch
import re
import socket
import traceback
import tempfile
import threading
import functools
import errno
import shutil
import otphashcheck

from info_gather import store_app_exception

OTP_HOME = "/opt/otp/"
SYSINFO_FILE = 'systeminfo.txt'

KNOWN_COMPONENTS = ("rest",)

system_info = None  # systeminfo.txt file obj; if you want to use reporting
# functions externally, set this as desired.


# the general logger; gets to diag.log & screen
logger = logging
# only goes to diag.log (or a temp file on failure), used for adding additional
# info that isn't helpful onscreen
auxlogger = logging


# These two are initialized to the 'logging' module, so there's some kind of log
# behavior no matter what; but they're really set up in logging_horrorshow()

# =====================================
# === ВСЯКАЯ ВРЕМЕННАЯ ШНЯГА _tmpsh ===
# =====================================
app_info_dict = {}

def logging_horrorshow():
    disable_clilib_logger()
    buffer_obj = setup_buffer_logger()
    setup_main_logger()
    return buffer_obj

def app_ext_names():
    "returns the list of apps with diag extensions configured"
    return list(app_info_dict.keys())

def ot_failure():
    print("4toto poshlo ne tak")

def app_components():
    "returns a tuple of the component names for apps with diag extensions"
    return tuple(app.component_name for app in app_info_dict.values())

def local_getopt(file_options, cmd_argv=sys.argv):
    "Implement cmdline flag parsing using optparse"

    def set_components(option, opt_str, value, parser):
        "Override any existing set of enabled components with the provided string"
        if not value:
            raise optparse.OptionValueError("--collect argument missing")

        components = value.split(",")
        all_components = set(KNOWN_COMPONENTS).union(set(app_components()))
        if 'all' in components:
            parser.values.components = all_components
        else:
            req_components = set(components)
            unknown_components = req_components.difference(all_components)
            if unknown_components:
                as_string = ",".join(unknown_components)
                raise optparse.OptionValueError("Unknown components requested: " + as_string)
            parser.values.components = req_components

    def enable_component(option, opt_str, value, parser):
        "Add one component to the enabled set of components"
        component = value
        if component not in (KNOWN_COMPONENTS + app_components()):
            raise optparse.OptionValueError("Unknown component requested: " + component)
        elif component in parser.values.components:
            logger.warn("Requested component '%s' was already enabled.  No action taken." % component)
        else:
            parser.values.components.add(component)

    def disable_component(option, opt_str, value, parser):
        "Remove one component from the enabled set of components"
        component = value
        if component not in (KNOWN_COMPONENTS + app_components()):
            raise optparse.OptionValueError("Unknown component requested: " + component)
        elif component not in parser.values.components:
            logger.warn("Requested component '%s' was already disabled.  No action taken." % component)
        else:
            parser.values.components.remove(component)

    def _parse_size_string(value, setting_name):
        "accept sizes like 10kb or 2GB, returns value in bytes"
        sizemap = {"b":      1,
                   "kb": 2**10,
                   "mb": 2**20,
                   "gb": 2**30,
                   "tb": 2**40,
                   "pb": 2**50,   # perhaps being too completeist here
        }
        numbers = re.match('^\d+', value)
        if not numbers:
            msg = "Could not find integer in %s target '%s'" % (setting_name, value)
            raise optparse.OptionValueError(msg)
        base_number = int(numbers.group(0))
        rest = value[numbers.end():]

        if not rest:
            # no indication means kilobytes (history)
            rest = "kb"

        if not rest.lower() in sizemap:
            msg = "Could not understand '%s' as a size denotation" % rest
            raise optparse.OptionValueError(msg)
        number = base_number * sizemap[rest.lower()]
        return number

    def set_log_size_limit(option, opt_str, value, parser):
        "sets limit on files for var/log dir"
        number = _parse_size_string(value, "--log-filesize-limit")
        parser.values.log_filesize_limit = number

    def set_etc_size_limit(option, opt_str, value, parser):
        "sets limit on files for etc dir"
        number = _parse_size_string(value, "--etc-filesize-limit")
        parser.values.etc_filesize_limit = number

    # handle arguments
    parser = optparse.OptionParser(usage="Usage: splunk diag [options]")
    parser.prog = "diag"

    # yes, a negative option. I'm a bastard
    parser.add_option("--nologin", action="store_true",
                      help="override any use of REST logins by components/apps")

    parser.add_option("--auth-on-stdin", action="store_true",
                      help="Indicates that a local splunk auth key will be provided on the first line of stdin")

    component_group = optparse.OptionGroup(parser, "Component Selection",
                      "These switches select which categories of information "
                      "should be collected.  The current components available "
                      "are: " + ", ".join(KNOWN_COMPONENTS + app_components()))

    parser.add_option("--exclude", action="append",
                      dest="exclude_list", metavar="pattern",
                      help="glob-style file pattern to exclude (repeatable)")

    component_group.add_option("--collect", action="callback", callback=set_components,
                      nargs=1, type="string", metavar="list",
                      help="Declare an arbitrary set of components to gather, as a comma-separated list, overriding any prior choices")
    component_group.add_option("--enable", action="callback", callback=enable_component,
                      nargs=1, type="string", metavar="component_name",
                      help="Add a component to the work list")
    component_group.add_option("--disable", action="callback", callback=disable_component,
                      nargs=1, type="string", metavar="component_name",
                      help="Remove a component from the work list")

    parser.add_option("--uri",
                      dest="uri", metavar="url",
                      help="url of a management port of a remote splunk install from which to collect a diag.")

    parser.add_option_group(component_group)

    detail_group = optparse.OptionGroup(parser, "Level of Detail",
                      "These switches cause diag to gather data categories "
                      "with lesser or greater thoroughness.")

    detail_group.add_option("--include-lookups", action="store_true",
                      help="Include lookup files in the etc component [default: do not gather]")

    detail_group.add_option("--all-dumps", type="string",
                      dest="all_dumps", metavar="bool",
                      help="get every crash .dmp file, opposed to default of a more useful subset")
    detail_group.add_option("--index-files", default="manifests", metavar="level",
                      help="Index data file gathering level: manifests, or full (meaning manifests + metadata files) [default: %default]")
    detail_group.add_option("--index-listing", default="light", metavar="level",
                      help="Index directory listing level: light (hot buckets only), or full (meaning all index buckets) [default: %default]")

    etc_filesize_default="10MB"
    detail_group.add_option("--etc-filesize-limit", type="string",
                      default=_parse_size_string(etc_filesize_default, ""), action="callback",
                      callback=set_etc_size_limit, metavar="size",
                      help="do not gather files in $SPLUNK_HOME/etc larger than this. (accepts values like 5b, 20MB, 2GB, if no units assumes kb), 0 disables this filter [default: %s]" % etc_filesize_default)
    detail_group.add_option("--log-age", default="60", type="int", metavar="days",
                      help="log age to gather: log files over this many days old are not included, 0 disables this filter [default: %default]")

    log_filesize_default="1GB"
    detail_group.add_option("--log-filesize-limit", type="string",
                      default=_parse_size_string(log_filesize_default, ""), action="callback",
                      callback=set_log_size_limit, metavar="size",
                      help="fully gather files in $SPLUNK_HOME/var/log smaller than this size.  For log files larger than this size, gather only this many bytes from the end of the file (capture truncated trailing bytes). [default: %s]" % log_filesize_default)

    parser.add_option_group(detail_group)

    filter_group = optparse.OptionGroup(parser, "Data Filtering",
                      "These switches cause diag to redact or hide data from the output diag.")

    filter_group.add_option("--filter-searchstrings", action="store_true", dest="filtersearches",
                      default=True,
                      help="Attempt to redact search terms from audit.log & remote_searches.log that may be private or personally identifying")

    filter_group.add_option("--no-filter-searchstrings", action="store_false", dest="filtersearches",
                      help="Do not modify audit.log & remote_searches.log")

    parser.add_option_group(filter_group)

    output_group = optparse.OptionGroup(parser, "Output",
                      "These control how diag writes out the result.")

    output_group.add_option("--stdout", action="store_true", dest="stdout",
                      help="Write an uncompressed tar to standard out.  Implies no progress messages.")

    output_group.add_option("--diag-name", "--basename", metavar="name", dest="diagname",
                      help="Override diag's default behavior of autoselecting its name, use this name instead.")

    output_group.add_option("--statusfile", metavar="filename", dest="statusfile",
                      help="Write progress messages to a file specified by the given path. Useful with --stdout.")

    output_group.add_option("--debug", action="store_true", dest="debug",
                      help="Print debug output")

    parser.add_option_group(output_group)


    upload_group = optparse.OptionGroup(parser, "Upload",
                     "Flags to control uploading files\n Ex: splunk diag --upload")

    upload_group.add_option("--upload", action="store_true", dest="upload",
                      help="Generate a diag and upload the result to splunk.com")

    upload_group.add_option("--upload-file", metavar="filename",
                      dest="upload_file",
                      help="Instead of generating a diag, just upload a file")

    upload_group.add_option("--case-number", metavar="case-number",
                      type='int', dest="case_number",
                      help="Case number to attach to, e.g. 200500")

    upload_group.add_option("--upload-user", dest="upload_user",
                      help="splunk.com username to use for uploading")

    upload_group.add_option("--upload-description", dest="upload_description",
                      help="description of file upload for Splunk support")

    upload_group.add_option("--firstchunk", type="int", metavar="chunk-number",
                      help="For resuming upload of a multi-part upload; select the first chunk to send")

    parser.add_option_group(upload_group)

    # add any further parser config stuff for app extensions
    class Parser_Proxy(object):
        "proxy object for option parser to handle namespacing app options"
        def __init__(self, app_info, parser):
            self.app_info = app_info
            self.parser = parser
            self.optiongroup = None

        def add_option(self, *flags, **kwargs):
            if  ((len(flags) != 1) or (not flags[0].startswith('--'))):
                raise NotImplementedError("Diag extensions only support long opts (--foo -> --app.foo) for apps")

            # create an option group for the app, since it has at least one
            # flag. (visual help treatment)
            if not self.optiongroup:
                self.optiongroup = optparse.OptionGroup(self.parser,
                                                        "%s options" % self.app_info.component_name)

            #namespace and pass along the option add
            option_str = flags[0]
            proxied_flag = '--%s:%s' % (self.app_info.app_name, option_str.lstrip('-'))
            if 'dest' in  kwargs:
                if not 'metavar' in kwargs:
                    kwargs['metavar'] = kwargs['dest']
                kwargs['dest']  = "%s.%s" % (self.app_info.app_name, kwargs['dest'])
            self.optiongroup.add_option(proxied_flag, **kwargs)

        def _complete(self):
            "If any options were added, add the group to the parser"
            if self.optiongroup:
                self.parser.add_option_group(self.optiongroup)

    # setup hook for app to provide its own options
    for diag_ext_app in app_ext_names():
        app_info = get_app_ext_info(diag_ext_app)
        logger.debug("app_info: %s" % app_info)
        # set up a proxy object to namespace app options
        parser_proxy = Parser_Proxy(app_info, parser)
        callback = Extension_Callback()
        try:
            app_info.module_obj.setup(parser=parser_proxy,
                                      app_dir=app_info.app_dir,
                                      callback=callback)
        except Exception as e:
            # for any kind of failure, log an error, store the exception in
            # the app_info object, and turn off collection for the app later.
            exception_text = traceback.format_exc()
            msg = "Diag extensions: App %s threw an exception during setup(). No Extension collection will happen for this app, exception text will be stored in the diag at %s."
            output_path = os.path.join("app_ext", diag_ext_app, "setup_failed.output")
            logger.error(msg, diag_ext_app, output_path)

            invalidate_app_ext(diag_ext_app)
            store_app_exception(diag_ext_app, exception_text)

        parser_proxy._complete()

    # diag-collect every category, except REST, by default
    # no REST for now  because there are too many question marks about reliability
    default_components = set(KNOWN_COMPONENTS) | set(app_components())
    default_components.remove('rest')
    parser.set_defaults(components=default_components)

    # override above defaults with any from the server.conf file
    parser.set_defaults(**file_options)

    options, args =  parser.parse_args(cmd_argv)

    if options.index_files not in ('manifests', 'manifest', 'full'):
        parser.error("wrong value for index-files: '%s'" % options.index_files)

    if options.index_listing not in ('light', 'full'):
        parser.error("wrong value for index-listing: '%s'" % options.index_listing)

    if options.upload and options.upload_file:
        parser.error("You cannot use --upload and --upload-file in one command")

    if options.upload_file:
        try:
            f = open(options.upload_file)
            f.close()
        except (IOError, OSError) as e:
            parser.error("Cannot open file %s for reading: %s" %
                         (options.upload_file, e.strerror))
    elif options.upload_file == "":
        parser.error("Empty-string is not a valid argument for --upload-file")

    if not (options.upload or options.upload_file) and (
               options.upload_user or
               options.case_number or
               options.upload_description):
        parser.error("Upload values provided, but no upload mode chosen: you need --upload or --upload-file")

    return options, args

# ========================================================
# === TEMLATE FUNCTION FOR ADDING CREATED FILE TO DIAG ===
# ========================================================

'''def copy_something_to_diag():
    add_file_to_diag(file_path, diag_path)
    dir_to_add = os.path.join("opt, "dir", "to", "add")
    add_file_to_diag(src_file, os.path.join("dispatch", job, f))'''

# ===============================================================================
# === ВРЕМЕННО ВКЛЮЧЕННЫЕ ФУНКЦИИ ДЛЯ ТОГО, ЧТОБЫ РАБТАЛО СОЗДАНИЕ TAR АРХИВА ===
# ===============================================================================
'''
excluded_filelist = []


def reset_excluded_filelist():
    "Wipe it, just in case we ever make this module persistent"
    global excluded_filelist
    excluded_filelist = []


def build_filename_filters(globs):
    if not globs:
        return []
    glob_to_re = lambda s: re.compile(fnmatch.translate(s))
    return list(map(glob_to_re, globs))


def set_storage_filters(filter_list):
    global _storage_filters
    _storage_filters = filter_list

'''
# ====================================================================================================================
# === СОЗДАЕМ ЭКЗЕМПЛЯР КЛАССА DirectTar - ЭТО, ПО СУТИ БУДУЩИЙ АРХИВ С РАЗЛИЧНЫМИ МЕТОДАМИ ДОДАВЛЕНИЯ В НЕГО ИНФЫ ===
# ====================================================================================================================

storage = None
def set_storage():
    global storage
    storage = DirectTar()

##################
# Scaffolding for accepting data to add to the diag
# ==========================================================================
# === ПО СУТИ БУДУЩИЙ АРХИВ С РАЗЛИЧНЫМИ МЕТОДАМИ ДОДАВЛЕНИЯ В НЕГО ИНФЫ ===
# ==========================================================================
class DirectTar(object):
    # Инициазируем класс
    # Переменная stored_dirs хранит набор путей каталогов,
    # чтобы мы могли использовать их при создании архива
    def __init__(self, compressed=True):
        self.compressed = compressed
        self.stored_dirs = set()
    # Открывает на запись gzip файл
    def setup(self, options):
        self.tarfile = tarfile.open(get_tar_pathname(), 'w:gz', compresslevel=6)
        self._add_empty_named_dir(get_diag_name())

    # Создаёт пустой каталог в архиве
    def _add_empty_named_dir(self, diag_path):
        "Add a directory of a particular name, for tar completeness"
        logger.debug("_add_empty_named_dir(%s)" % diag_path)
        tinfo = tarfile.TarInfo(diag_path)
        tinfo.type = tarfile.DIRTYPE
        tinfo.mtime = time.time()
        tinfo.mode = 0o755  # dir needs x
        self.tarfile.addfile(tinfo)
        self.stored_dirs.add(diag_path)

    # Создаём структу родительских каталогов проверяем корректность путей
    def _add_unseen_parents(self, file_path, diag_path):
        """Add all parents of a dir/file of a particular name,
           that are not already in the tar"""
        logger.debug("_add_unseen_parents(%s, %s)" % (file_path, diag_path))
        parents = []
        src_dir = file_path
        tgt_dir = diag_path
        # we are looking for two goals here:
        # 1 - create an entry in the tar so we get sane behavior on unpack
        # 2 - if the source dir is from a file inside OTP_HOME, the dir
        #     entries should match the permissions, timestamps,
        if file_path.startswith(OTP_HOME):
            while True:
                logger.debug("_add_unseen_parents() -> tgt_dir=%s src_dir=%s", tgt_dir, src_dir)
                prior_tgt_dir = tgt_dir
                prior_src_dir = src_dir
                tgt_dir = os.path.dirname(tgt_dir)
                src_dir = os.path.dirname(src_dir)
                if not tgt_dir or tgt_dir == "/" or tgt_dir == get_diag_name() or tgt_dir == prior_tgt_dir:
                    break
                if not src_dir or src_dir in ("/", "\\") or src_dir == prior_src_dir:
                    # This is here because this case almost certainly represents
                    # a logic bug (one existed at some point)
                    raise Exception("Wtf.  " +
                                    "You copied a shorter source dir into a longer target dir? " +
                                    "Does this make sense in some universe? " +
                                    "args were: file_path=%s diag_path=%s" % (file_path, diag_path))
                if not tgt_dir in self.stored_dirs:
                    parents.append((src_dir, tgt_dir))
            if not parents:
                return
            logger.debug("_add_unseen_parents --> parents:(%s)" % parents)
            parents.reverse()  # smallest first
            for src_dir, tgt_dir in parents:
                if os.path.islink(src_dir) or not os.path.isdir(src_dir):
                    # We can't add a non-directory as a parent of a directory
                    # or file, extracting will fail or be unsafe.
                    # it should be a symlink
                    if os.path.islink(src_dir):
                        # XXX change to auxlogger
                        msg = "Encountered symlink: %s -> %s; storing as if plain directory. Found adding parent dirs of %s."
                        logging.warn(msg, src_dir, os.readlink(src_dir), file_path)
                        # for symlinks, we want to get the perm data from the
                        # target, since owner/perm/etc data on a symlink has no
                        # meaning.
                        symlink_target = os.path.realpath(src_dir)
                        if not os.path.exists(symlink_target):
                            logging.error("Link target does not exist(!!)")
                            tarinfo = self.tarfile.gettarinfo(src_dir, arcname=tgt_dir)
                        else:
                            tarinfo = self.tarfile.gettarinfo(symlink_target, arcname=tgt_dir)
                    else:
                        # This should not be a possible branch, but paranoia
                        msg = "Encountered unexpected filetype: %s stat: %s storing as if directory. Found adding parent dirs of %s."
                        logging.warn(msg, src_dir, os.stat(src_dir), file_path)
                        tarinfo = self.tarfile.gettarinfo(src_dir, arcname=tgt_dir)
                    # Either way, pretend it's a directory
                    tarinfo.type = tarfile.DIRTYPE
                    self.tarfile.addfile(tarinfo)
                else:
                    self.tarfile.add(src_dir, arcname=tgt_dir, recursive=False)
                self.stored_dirs.add(tgt_dir)
        else:
            # we're adding a file from outside OTP_HOME.  Probably a temp
            # file.  TODO -- should we enforce something here?
            while True:
                logger.debug("_add_unseen_parents() outside SPLUNK_HOME -> tgt_dir=%s", tgt_dir)
                prior_tgt_dir = tgt_dir
                tgt_dir = os.path.dirname(tgt_dir)
                if not tgt_dir or tgt_dir == "/" or tgt_dir == get_diag_name() or tgt_dir == prior_tgt_dir:
                    break
                if not tgt_dir in self.stored_dirs:
                    parents.append(tgt_dir)
            if not parents:
                return
            logger.debug("_add_unseen_parents --> parents:(%s)" % parents)
            parents.reverse()  # smallest first
            for dir in parents:
                self._add_empty_named_dir(tgt_dir)
    # Закрывает tar-файл
    def complete(self):
        self.tarfile.close()
    # Добавляет файл в архив
    def add(self, file_path, diag_path):
        logger.debug("add(%s)" % file_path)
        if diag_path in self.stored_dirs:
            # nothing to do
            return
        try:
            self._add_unseen_parents(file_path, diag_path)
            if os.path.isdir(file_path):
                self.stored_dirs.add(diag_path)
            self.tarfile.add(file_path, diag_path, recursive=False)
        except IOError as e:
            # report fail, but continue along
            err_msg = "Error adding file '%s' to diag, failed with error '%s', continuing..."
            logger.warn(err_msg % (file_path, e))
            pass
    # Добавляет директорию в архив
    def add_dir(self, dir_path, diag_path, ignore=None):
        logger.debug("add_dir(%s)" % dir_path)
        adder = functools.partial(add_file_to_diag, add_diag_name=False)
        collect_tree(dir_path, diag_path, adder, ignore=ignore)

# ==========================
# === ПОЛУЧАЕМ ИМЯ ДИАГА ===
# ==========================

def get_diag_date_str():
    return datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')


def format_diag_name(host_part):
    date_str = get_diag_date_str()
    return "diag-%s-%s" % (host_part, date_str)


diag_name = None

def get_otp_name():
    return socket.gethostname()


def get_diag_name(base=None):
    """Construct the diag's name,
       used both for paths inside and for the containing tarname"""
    # hack to create 'static' value
    global diag_name
    if not diag_name:
        if not base:
            base = get_otp_name()
        diag_name = format_diag_name(base)
        # logger.info('Selected diag name of: ' + diag_name)
    return diag_name


def format_tar_name(basename, compressed=True):
    """ Construct a filename for the diag """
    extension = ".tar"
    if compressed:
        extension += ".gz"
    return basename + extension


def get_tar_pathname(filename=None, compressed=True):
    """ Construct the output pathname for the diag """
    if not filename:
        filename = get_diag_name()
    tar_filename = format_tar_name(filename)

    # TODO: give user control over output dir/path entirely
    return (os.path.join(OTP_HOME, tar_filename))


# ======================================
# === ДОБАВИТЬ ФАЙЛ ИЛИ КАТАЛОГ К БОЛШОМУ DIAG'У ===
# ======================================

def add_file_to_diag(file_path, diag_path, add_diag_name=True):
    if add_diag_name:
        diag_path = os.path.join(get_diag_name(), diag_path)
    storage.add(file_path, diag_path)

def add_dir_to_diag(dir_path, diag_path, ignore=None):
    diag_path = os.path.join(get_diag_name(), diag_path)
    storage.add_dir(dir_path, diag_path, ignore=ignore)

# ==========================================================
# === УТИЛИТЫ КОМАНДНОЙ СТРОКИ, НАПРИМЕР, СБОР ОКРУЖЕНИЯ ===
# ==========================================================

# == Get conf files ==

def get_conf(dir):
    for address, dirs, files in os.walk(dir):
        for file in files:
            file = os.path.join(address, file)
            pattern_conf = "(.*\.(conf|xml|sh|properties|xsl))$"
            conf_file = re.match(pattern_conf, file)
            if conf_file is None:
                pass
            else:
                print("-----------\n", "Copy config file:",
                      conf_file.group(0), "to diag-file")
                add_file_to_diag(conf_file.group(0), conf_file.group(0))

def networkConfig():
    """ Network configuration  """

    # system_info.write('\n\n********** Network Config  **********\n\n')
    # we call different utilities for windows and "unix".
    if os.name == "posix":
        # if running as a non-root user, you may not have ifconfig in your path.
        # we'll attempt to guess where it is, and if we can't find it, just
        # assume that it is somewhere in your path.
        ifconfig_exe = '/sbin/ifconfig'
        if not os.path.exists(ifconfig_exe):
            ifconfig_exe = 'ifconfig'
        exit_code, output = simplerunner([ifconfig_exe, "-a"], timeout=3)
    else:
        exit_code, output = simplerunner(["ipconfig", "/all"], timeout=3)
    if output:
        system_info.write(output)
        print("-----------\n", "Network output here:")
        # print(output)


# === main() ===
def create_diag():

    # initialize whatever is needed for the storage type
    file_options = {}
    options, args = local_getopt(file_options)

    storage.setup(options)

    sysinfo_filename = None
    try:
        try:
            global system_info
            system_info = tempfile.NamedTemporaryFile(prefix="splunk_sysinfo", mode="w+", delete=False)
            sysinfo_filename = system_info.name
        except IOError:
            # logger.error("Exiting: Cannot create system info file.  Permissions may be wrong.")
            # write_logger_buf_on_fail(log_buffer)
            sys.exit(1)
        # ifconfig
        networkConfig()
    finally:
        system_info.close()
    # добавляем файл с системным окружением в diag
    try:
        add_file_to_diag(sysinfo_filename, SYSINFO_FILE)
        print(sysinfo_filename, SYSINFO_FILE)
    finally:
        os.unlink(sysinfo_filename)

    # get config files
    get_conf(OTP_HOME)

# === main() ===

def main():
    manifest_list = otphashcheck.dict_dir("/opt/otp/SuperDispatcher")
    otphashcheck.save_manifest(manifest_list,"/opt/otp/manifest.json")
    set_storage()
    hostname = socket.gethostname()
    print("-----------\n", "Hostname:", hostname)
    tar_pathname = get_tar_pathname()
    print("-----------\n", "Path_diag:", tar_pathname)
    options = {}
    create_diag()

###################
# internal utility

def collect_tree(src, dst, actor, ignore=None):
    """Recursively walk a a directory tree, applying a function to each entry.
    Made for adding files to tar, a dir.

    If exception(s) occur, an Error is raised with a list of reasons.

    actor is a callable, which must accept src, the path to a real file, and
    dst, target path within the described namespace.

    The optional ignore argument is a callable. If given, it
    is called with the `src` parameter, which is the directory
    being visited by copytree(), and `names` which is the list of
    `src` contents, as returned by os.listdir():

        callable(src, names) -> ignored_names

    Since collect_tree() is called recursively, the callable will be
    called once for each directory that is copied. It returns a
    list of names relative to the `src` directory that should
    not be copied.
    """
    names = os.listdir(src)
    if ignore is not None:
        ignored_names = ignore(src, names)
    else:
        ignored_names = set()

    actor(src, dst)
    errors = []
    for name in names:
        if name in ignored_names:
            continue
        srcname = os.path.join(src, name)
        dstname = os.path.join(dst, name)
        try:
            if os.path.isdir(srcname):
                collect_tree(srcname, dstname, actor, ignore)
            else:
                # Will raise a SpecialFileError for unsupported file types
                actor(srcname, dstname)
        # catch the Error from the recursive copytree so that we can
        # continue with other files
        except shutil.Error as err:
            errors.extend(err.args[0])
        except EnvironmentError as why:
            errors.append((srcname, dstname, str(why)))
    # XXX Hack: have to give a chance to set modtime at the end
    actor(src, dst)
    if errors:
        raise shutil.Error(errors)

def simplerunner(cmd, timeout, description=None, input=None):
    """ Using PopenRunner directly every time is tedious.  Do the typical stuff.

        cmd         :iterable of strings, eg argv
        timeout     :time to give the command to finish in seconds before it is
                     brutally killed
        description :string for logging about the command failing etc
        input       :string to stuff into stdin pipe the command
    """
    cmd_string = " ".join(cmd)
    if not description:
        description = cmd_string
    opener = functools.partial(subprocess.Popen, cmd,
                               stdout=subprocess.PIPE, shell=False)
    runner = PopenRunner(opener, description=description)
    exit_code = runner.runcmd(timeout=timeout, input=input)
    out = runner.stdout
    if not out:
        out = "The command '%s' was cancelled due to timeout=%s\n" % (cmd_string, timeout)
    return exit_code, out


class PopenRunner(object):
    """ Run a popen object (passed in as a partial) with a timeout

        opener = functools.partial(subprocess.Popen, cmd=["rm", "/etc/passwd"], arg=blah, another_arg=blee)
        runner = PopenRunner(opener, description="password destroyer")
        returncode = runner.runcmd(timeout=15)
        print(runner.stdout)
        print(runner.stderr)
    """

    def __init__(self, popen_f, description=None):
        """popen_f     :function that when called, returns a Popen object
           description :string for logging about the command failing etc
        """
        self.opener = popen_f
        self.description = description
        self.p_obj = None
        self.stdout = None
        self.stderr = None
        self.exception = None
        self.traceback = None

    def runcmd(self, timeout=10, input=None):
        """timeout     :time to give the command to finish in seconds
           input       :string to stuff into stdin pipe for command
        """

        def inthread_runner(input=input):
            try:
                self.p_obj = self.opener()
                if (input is not None) and sys.version_info >= (3, 0): input = input.encode()
                self.stdout, self.stderr = self.p_obj.communicate(input=input)
                if sys.version_info >= (3, 0):
                    self.stdout = self.stdout.decode()
                    if self.stderr is not None:
                        self.stderr = self.stderr.decode()
            except Exception as e:
                class fake_pobj(object):
                    pass

                if isinstance(e, OSError) and e.errno in (errno.ENOENT, errno.EPERM, errno.ENOEXEC, errno.EACCES):
                    # the program wasn't present, or permission denied; just report that.

                    # Aside: Popen finds out about the problem during a read call on the
                    # pipe, so the exception doesn't know the filename, and we
                    # don't here either.  Sad.

                    # we'll fib a bit and claim the errror desc is the output, for
                    # consumer purposes
                    self.stdout = str(e)
                    self.stderr = str(e)

                    # However, if they really want to know, the returncode will
                    # tell them the command did not run (this will be the return
                    # value of runcmd)
                    self.p_obj = fake_pobj()
                    self.p_obj.returncode = 127

                else:
                    # for everything else we want the stack to log
                    self.exception = e
                    self.traceback = traceback.format_exc()

                    self.p_obj = fake_pobj()
                    self.p_obj.returncode = -1

        thread = threading.Thread(target=inthread_runner)
        thread.start()
        thread.join(timeout)

        def log_action(action):
            if self.description:
                logger.warn("%s %s." % (action, self.description))
            else:
                logger.warn("%s stalled command." % (action,))

        if thread.is_alive():
            log_action("Terminating")
            if self.p_obj:  # the thread may not have set p_obj yet.
                self.p_obj.terminate()
            else:
                logger.warn("Unexpectedly tearing down a thread which never got started.")
            time.sleep(0.2)
            if thread.is_alive():
                log_action("Killing")
                if self.p_obj:  # the thread may not have set p_obj yet.
                    self.p_obj.kill()
                else:
                    logger.error("A python thread has completely stalled while attempting to run: %s" % (
                                self.description or "a command"))
                    logger.error("Abandoning that thread without cleanup, hoping for the best")
                    return 1
            thread.join()

        if self.exception:
            logger.error("Exception occurred during: %s" % (self.description or "a command"))
            logger.error(self.traceback)

        return self.p_obj.returncode


#######
# direct-run startup, normally splunk diag doesn't use this but
# splunk cmd python info_gather.py goes through here.

if __name__ == "__main__":
    main()
