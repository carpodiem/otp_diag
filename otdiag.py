# -*- coding: utf-8 -*-

import os
import subprocess
import sys
import tarfile
import datetime
import time  # two time modules, zzz
import optparse
import re
import socket
import tempfile
import threading
import functools
import otphashcheck

OTP_HOME = "/opt/otp/"
#SPLUNK_HOME   = os.environ['SPLUNK_HOME']

#SPLUNK_HOME   = '/opt/splunk'
RESULTS_LOC = os.path.join(OTP_HOME, 'diag-temp')
SYSINFO_FILE  = 'systeminfo.txt'

# Компоненты конфигурации Платформы для их сбора в диаг
KNOWN_COMPONENTS = ("configs",
                    "checksums",
                    "sysinfo",
                    )
'''KNOWN_COMPONENTS = ("index_files",
                    "index_listing",
                    "dispatch",
                    "etc",
                    "log",
                    "searchpeers",
                    "consensus",
                    "conf_replication_summary",
                    "suppression_listing",
                    "rest",
                    "kvstore",
                    "file_validate",
                    )'''


# Берет now - дату для имени диага
def get_diag_date_str():
    return datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

# Получаем имя хоста для использования как часть имени диага
def get_splunkinstance_name():
    # Octavio says the hostname is preferred to machine-user, and that
    # multiple-splunks-per-host is now rare, so just use hostname
    return socket.gethostname()


# Имя диага =  имя хоста + дата
def format_diag_name(host_part):
    date_str = get_diag_date_str()
    return "diag-%s-%s" % (host_part, date_str)

# Получить имя диага
diag_name = None
def get_diag_name(base=None):
    """Construct the diag's name,
       used both for paths inside and for the containing tarname"""
    # hack to create 'static' value
    global diag_name
    if not diag_name:
        if not base:
            base = get_splunkinstance_name()
        diag_name = format_diag_name(base)
        # logger.info('Selected diag name of: ' + diag_name)
    return diag_name

# Задает имя диага, если оно явно определено в параметрах командной строки
def set_diag_name(name):
    global diag_name
    diag_name = name
    #logger.info('Set diag name to: ' + diag_name)

# Конструируем имя архива (путь+имя) из имени диага
def format_tar_name(basename, compressed=True):
    """ Construct a filename for the diag """
    extension = ".tar"
    if compressed:
        extension += ".gz"
    return basename + extension

# Конструируем имя архива (путь+имя) из имени диага
def get_tar_pathname(filename=None, compressed=True):
    """ Construct the output pathname for the diag """
    if not filename:
        filename = get_diag_name()
    tar_filename = format_tar_name(filename)

    # TODO: give user control over output dir/path entirely
    return (os.path.join(OTP_HOME, tar_filename))


# Scaffolding for accepting data to add to the diag
# Класс для tar-архива и методы манипуляции с ним.
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
        y=get_diag_name()
        print("diag name :" , y)
        self._add_empty_named_dir(get_diag_name())

    # Создаёт пустой каталог в архиве
    def _add_empty_named_dir(self, diag_path):
        "Add a directory of a particular name, for tar completeness"
        #logger.debug("_add_empty_named_dir(%s)" % diag_path)
        tinfo = tarfile.TarInfo(diag_path)
        tinfo.type = tarfile.DIRTYPE
        tinfo.mtime = time.time()
        tinfo.mode = 0o755  # dir needs x
        self.tarfile.addfile(tinfo)
        self.stored_dirs.add(diag_path)

    # Создаём структу родительских каталогов проверяем корректность путей
    # что за структура, нас она устраивает ???
    def _add_unseen_parents(self, file_path, diag_path):
        """Add all parents of a dir/file of a particular name,
           that are not already in the tar"""
        #logger.debug("_add_unseen_parents(%s, %s)" % (file_path, diag_path))
        parents = []
        src_dir = file_path
        tgt_dir = diag_path
        # we are looking for two goals here:
        # 1 - create an entry in the tar so we get sane behavior on unpack
        # 2 - if the source dir is from a file inside OTP_HOME, the dir
        #     entries should match the permissions, timestamps,
        if file_path.startswith(OTP_HOME):
            while True:
                #logger.debug("_add_unseen_parents() -> tgt_dir=%s src_dir=%s", tgt_dir, src_dir)
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
            #logger.debug("_add_unseen_parents --> parents:(%s)" % parents)
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
                #logger.debug("_add_unseen_parents() outside SPLUNK_HOME -> tgt_dir=%s", tgt_dir)
                prior_tgt_dir = tgt_dir
                tgt_dir = os.path.dirname(tgt_dir)
                if not tgt_dir or tgt_dir == "/" or tgt_dir == get_diag_name() or tgt_dir == prior_tgt_dir:
                    break
                if not tgt_dir in self.stored_dirs:
                    parents.append(tgt_dir)
            if not parents:
                return
            #logger.debug("_add_unseen_parents --> parents:(%s)" % parents)
            parents.reverse()  # smallest first
            for dir in parents:
                self._add_empty_named_dir(tgt_dir)
    # Закрывает tar-файл
    def complete(self):
        self.tarfile.close()
    # Добавляет файл в архив
    def add(self, file_path, diag_path):
        #logger.debug("add(%s)" % file_path)
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
            #logger.warn(err_msg % (file_path, e))
            pass
    # Добавляет директорию в архив
    def add_dir(self, dir_path, diag_path, ignore=None):
        #logger.debug("add_dir(%s)" % dir_path)
        adder = functools.partial(add_file_to_diag, add_diag_name=False)
        collect_tree(dir_path, diag_path, adder, ignore=ignore)


# Создает storage типа tar. Похоже, это единственный тип stotage.
# Есть еще тип memory и directory. Что это, неизвестно.
# То есть тип storage кажется лишней сущносью. Рассмотреть возможность упростить.
storage = None
def set_storage(style):
    global storage
    if style == "directory":
        storage = OutputDir()
    elif style == "tar":
        storage = DirectTar()
    else:
        raise "WTF"


# Без комментариев
def add_fake_special_file_to_diag(file_path, diag_path, special_type):
    "Add a hinty, zero-byte file that suggests there was a special file"
    name = "%s.%s" % (diag_path, special_type)
    storage.add_fake_file(file_path, name)

# Добавление файла в диаг
def add_file_to_diag(file_path, diag_path, add_diag_name=True):
    """Add a single file: file_path points to file on disk,
                          diag_path says where to store in the tar"""
    #logger.debug("add_file_to_diag(%s, %s)" % (file_path, diag_path))

    # all files live in the diag prefix
    if add_diag_name:
        diag_path = os.path.join(get_diag_name(), diag_path)

    # Исключаем фильтрацию, которая пока не реализована или не используется
    '''
    if path_unwanted(diag_path):
        add_excluded_file(diag_path)
        return
        '''

    # Исключаем фильтрацию, которая пока не реализована или не используется
    '''
    if wants_filter(diag_path):
        add_filtered_file_to_diag(file_path, diag_path)
        return
        '''

    # Исключаем фильтрацию, которая пока не реализована или не используется
    # We don't put in block devices, sockets, etc in the tar.
    # No booby-traps
    '''
    special_type = is_special_file(file_path)
    if special_type:
        add_fake_special_file_to_diag(file_path, diag_path, special_type)
        return
        '''
    #print(file_path, diag_path)
    storage.add(file_path, diag_path)


# Без комментариев
def add_filtered_file_to_diag(file_path, diag_path):
    """ Add the contents of a readable object (like an open file) to the
        diag at diag_path """
    filterclass = get_filter(diag_path)
    with open(file_path, "rb") as f:
        filtering_object = filterclass(f)

        storage.add_fileobj(filtering_object, diag_path)
        filtering_object.log_stats(diag_path)
        filtering_object.close()


# Добавление каталога в diag. Закомментирована пока избыточная часть.
def add_dir_to_diag(dir_path, diag_path, ignore=None):
    """Add a single file: dir_path points to dir on disk,
                          diag_path says where to store it (and its children) in the tar"""
    diag_path = os.path.join(get_diag_name(), diag_path)
    storage.add_dir(dir_path, diag_path, ignore=ignore)

##################
# фунции для сбора данных
# functions to gather data
# От какого пользователя работаем...
# !!! Может быть первоочередной задачей
def systemUsername():
    if os.name == 'posix':
        import pwd
        # get the name for the UID for the current process
        username = pwd.getpwuid(os.getuid())[0]
    elif os.name == 'nt':
        # thanks internets -- http://timgolden.me.uk/python/win32_how_do_i/get-the-owner-of-a-file.html`
        #pylint: disable=F0401
        import win32api
        import win32con
        username = win32api.GetUserNameEx(win32con.NameSamCompatible)
    else:
        username = 'unknown for platform:' + os.name
    system_info.write('diag launched by: %s\n' % username)
    system_info.write('\n')


# Сбор информации о ядре. Убрать SPLUNK. Убрать Windows.
# this uses python's uname function to get info in a cross-platform way.
'''
def systemUname():
    """ Python uname output """

    system_info.write('\n\n********** Uname **********\n\n')
    suname = platform.uname()[:]
    system_info.write(str(suname))
    #SPL-18413
    system_info.write("\n")
    system_info.write('\n\n********** splunkd binary format **********\n\n')
    splunkdpath = os.path.join(SPLUNK_HOME, 'bin', 'splunkd')
    if suname[0] == 'Windows':
        splunkdpath += ".exe"
    arch = str(platform.architecture(splunkdpath))
    system_info.write(arch)
    if suname[0] == 'Linux':
        system_info.write('\n\n********** Linux distribution info **********\n\n')

        cmd_args = ['lsb_release', '-a']
        system_info.write("running: %s\n" % " ".join(cmd_args))

        lsbinfo_opener = functools.partial(subprocess.Popen, cmd_args,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=False)
        lsbinfo_desc = "lsb_release run for more detailed distribution version info"
        lsbinfo_runner = PopenRunner(lsbinfo_opener, description=lsbinfo_desc)
        lsbinfo_exit_code = lsbinfo_runner.runcmd()
        if lsbinfo_runner.stdout:
            output=lsbinfo_runner.stdout
        elif lsbinfo_runner.traceback:
            output=lsbinfo_runner.traceback
        else:
            output="trouble running lsb_release -- oddly with no exception captured"
        system_info.write(output + '\n')
        '''

# Сбор конфигурационных файлов платформы
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

# Сбор конфигурации сети. Убрать Windows.
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

# Сбор информации о процессах (-nix операционные сиситемы)
'''
def get_process_listing_unix():
    lines = []
    lines.append("********** Process Listing (ps)  **********")
    lines.append("")

    suname = platform.uname()
    if suname[0] in ('Darwin', 'Linux', 'FreeBSD'):
        # systems known to support BSD-ps
        cmd = ["ps", "aux"]
    else:
        # the drek
        cmd = ["ps", "-elf"]
    lines.append("running: %s" % " ".join(cmd))
    exit_code, output = simplerunner(cmd, timeout=3)
    if output:
        output_lines = output.split("\n")
        splunk_lines = [line for line in output_lines if "splunk" in line]
    lines.extend(splunk_lines)
    return "\n".join(lines)
    '''


# Запуск сбора информации о процессах (и Win- и Nix- операционные сиситемы)
def get_process_listing():
    """ what programs are running? """
    if os.name == "nt":
        return get_process_listing_windows()
    else:
        return get_process_listing_unix()



# Сбор netstat
'''
def networkStat():
    """ Network Status """

    system_info.write('\n\n********** Network Status **********\n\n')
    # just like with ifconfig, we attempt to guess the path of netstat.
    # if we can't find it, we leave it up to it being in your path.
    # also, if we're on windows, just go with the path-less command.
    netstat_exe = '/bin/netstat'
    if not os.name == "posix" or not os.path.exists(netstat_exe):
        netstat_exe = 'netstat'
    # special-case linux to get linux specific processname info
    if sys.platform.startswith("linux"):
        exit_code, output = simplerunner([netstat_exe, "-a", "-n", "-p"], timeout=3)
    else:
        exit_code, output = simplerunner([netstat_exe, "-a", "-n"], timeout=3)
    system_info.write(output)
    '''


# Сбор системных ресурсов
'''
def systemResources():
    """ System Memory """

    # on windows, we use msinfo to get all the relevant output.
    if os.name == "posix":
        system_info.write('\n\n********** System Ulimit **********\n\n')
        exit_code, output = simplerunner(["/bin/sh", "-c", "ulimit -a"], timeout=1)
        system_info.write(output)
        system_info.write('\n\n********** System Memory **********\n\n')
        suname = platform.uname()
        #SPL-17593
        if suname[0] == 'SunOS':
            # is it worth converting this? i am le tired.
            system_info.write(os.popen('/usr/sbin/prtconf | head -3').read())
        elif suname[0] == 'Darwin':
            exit_code, output = simplerunner(["vm_stat"], timeout=1)
        elif suname[0] == 'Linux':
            exit_code, output = simplerunner(["free"], timeout=1)
            system_info.write(output)
        else:
            # try vmstat for hpux, aix, etc
            exit_code, output = simplerunner(["vmstat"], timeout=2)
            if output:
                system_info.write(output)
        system_info.write('\n\n********** DF output **********\n\n')
        exit_code, output = simplerunner(["df"], timeout=2)
        system_info.write(output)
        system_info.write('\n')

        system_info.write('also df -i\n')
        exit_code, output = simplerunner(["df", "-i"], timeout=2)
        system_info.write(output)

        system_info.write('\n\n********** mount output **********\n\n')
        exit_code, output = simplerunner(["mount"], timeout=2)
        system_info.write(output)
        system_info.write('\n\n********** cpu info **********\n\n')
        if suname[0] == 'SunOS':
            exit_code, output = simplerunner(["/usr/sbin/psrinfo", "-v"], timeout=2)
        elif suname[0] == 'Darwin':
            # how long does a system_profiler take?
            exit_code, output = simplerunner(["system_profiler", "SPHardwareDataType"], timeout=10)
        elif suname[0] == 'Linux':
            if os.path.exists('/proc/cpuinfo'):
                with open('/proc/cpuinfo') as cpuinfo:
                    output = cpuinfo.read()
            else:
                output = "/proc/cpuinfo unavailable. no /proc mounted?\n"
        elif suname[0] == 'AIX':
            aix_horror = """ for processor in `lsdev -c processor | awk '{ print $1; }'` ; do
                                echo $processor;
                                lsattr -E -l $processor;
                             done """
            # for this horror, we have to actually run the shell.  Poopies.
            # TODO use a processgroup with setsid and killpg
            aix_opener = functools.partial(subprocess.Popen, aix_horror,
                                       stdout=subprocess.PIPE, shell=True)
            aix_desc = "Overly complicated AIX cpu info fetcher hairball"
            aix_runner = PopenRunner(aix_opener, description=aix_desc)
            aix_exit_code = aix_runner.runcmd(timeout=15)
            if aix_exit_code != 0:
                logger.warn("non-zero exit code from the cpu info fetcher..  :-(")
                logger.warn("Please let us know if there are interesting errors.")
            if aix_runner.stdout:
                output=aix_runner.stdout
            else:
                output="trouble running the aix_horror\n"
        elif suname[0] == 'FreeBSD':
            # shell here too; linux  systcl has patternmatching, but not FreeBSD
            freebsd_blob = "sysctl -a | egrep -i 'hw.machine|hw.model|hw.ncpu'"
            freebsd_opener = functools.partial(subprocess.Popen, freebsd_blob,
                                               stdout=subprocess.PIPE, shell=True)
            freebsd_desc = "'sysctl -a' with egrep postfilter"
            freebsd_runner = PopenRunner(freebsd_opener, description=freebsd_desc)
            freebsd_runner.runcmd(timeout=2)
            output = freebsd_runner.stdout
            if not output:
                output = "trouble running the freebsd sysctl groveller\n"
        elif suname[0] == 'HP-UX':
            cmd_input = "selclass qualifier cpu;info;wait;infolog\n"
            exit_code, output = simplerunner(["cstm"],
                                             description="hpux cpu info command",
                                             timeout=15,
                                             input=cmd_input)
            if exit_code != 0:
                logger.warn("non-zero exit code from the hpux cpu info fetcher..  :-(")
                logger.warn("Please let us know if there are interesting errors.")
            if not output:
                output = "trouble running the hpux cpu info command\n"
        else:
            output = "access to cpu data not known for this platform.\n"
        system_info.write(output)

    else:
        get_msinfo()
        '''


# Информация о Splunk manifest
'''
def get_a_manifest(db_path, diag_base_path, manifest_filename):
    "Condensation of the below collectors"
    file_path = os.path.join(db_path, manifest_filename)
    if os.path.exists(file_path):
        diag_path = os.path.join(diag_base_path, manifest_filename)
        add_file_to_diag(file_path, diag_path)
        '''

# Информация о Splunk manifest бакетов
'''
def get_bucketmanifest_files(db_path, diag_base_path):
    """return relative paths for the .bucketManifest file under a given path (hopefully a SPLUNK_DB or index)
     reqested by vishal, SPL-31499"""
    get_a_manifest(db_path, diag_base_path, ".bucketManifest")
    '''

# Информация о Splunk manifest csv файлов
'''
def get_manifest_csv_files(db_path, diag_base_path):
    """return relative path for the manifest.csv file under a given path;
       this file should only exist inside a volume summary (tsum or tstats summary)
       reqested by igor, SPL-91173"""
    get_a_manifest(db_path, diag_base_path, "manifest.csv")
    '''

# Информация о Splunk manifest чего-то еще...
'''
def get_worddata_files(db_path, diag_base_path):
    """add Host/Source/SourceTypes .data to the diag
    db_path:   a filesystem location from which to collect the files
    diag_path: where to store them inside the diag"""
    logger.debug("get_worddata_files: db_path=%s diag_base_path=%s" % (db_path, diag_base_path))

    wanted_filenames = ("Hosts.data", "Sources.data", "SourceTypes.data")

    for dir, subdirs, files in os.walk(db_path):
        # skip over dirs that are short lived and not considered desired data
        if dir.endswith("-tmp") or dir.endswith("-inflight"):
            continue
        index_relative_path = os.path.relpath(dir, db_path)
        logger.debug("db_path=%s dir=%s index_relative_path=%s" % (db_path, dir,
            index_relative_path))
        for filename in files:
            if filename in wanted_filenames:
                file_path = os.path.join(db_path, dir, filename)
                diag_path = os.path.join(diag_base_path, index_relative_path, filename)
                add_file_to_diag(file_path, diag_path)
                '''


# Утилита для запуска команд командной строки и сбора результата.
# Запускает процессы/программы из Python
# Используется в том числе для сбора системного окружения (netstat, ifconfig)
###################
# internal utility
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

# Класс для simplerunner
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
        # закомментировано все, что касается логириования
        '''
        def log_action(action):
            if self.description:
                logger.warn("%s %s." % (action, self.description))
            else:
                logger.warn("%s stalled command." %(action,))
                '''

        if thread.is_alive():
            log_action("Terminating")
            if self.p_obj: # the thread may not have set p_obj yet.
                self.p_obj.terminate()
            else:
                #logger.warn("Unexpectedly tearing down a thread which never got started.")
                print("вместо Splunk logger")
            time.sleep(0.2)
            if thread.is_alive():
                log_action("Killing")
                if self.p_obj: # the thread may not have set p_obj yet.
                    self.p_obj.kill()
                else:
                    logger.error("A python thread has completely stalled while attempting to run: %s" % (self.description or "a command"))
                    logger.error("Abandoning that thread without cleanup, hoping for the best")
                    return 1
            thread.join()

        if self.exception:
            #logger.error("Exception occurred during: %s" % (self.description or "a command"))
            #logger.error(self.traceback)
            print("вместо Splunk logger")

        return self.p_obj.returncode


# Чистит временные файлы
def clean_temp_files():
    "Wipe the diag-temp dir.  Probably obsolete" # TODO - kill?
    if os.path.isdir(RESULTS_LOC):
        for f in os.listdir(RESULTS_LOC):
            specific_tempdir = os.path.join(RESULTS_LOC, f)
            if os.path.isdir(specific_tempdir):
                deleteTree(specific_tempdir)


# Парсим аргументы командной строки с использованием optparce
def local_getopt(file_options, cmd_argv=sys.argv):
    "Implement cmdline flag parsing using optparse"

    # --- Callback функции для расширения стандартных "возможностей"  optparce
    # Используются для реализации таких операций как: добавление/исключение компонента платформы из сбора
    # Пока закомментировано. Релизовано только 'disable_component'

    def disable_component(option, opt_str, value, parser):
        "Исключает компонент платформы из сбора"
        component = value
        if component not in (KNOWN_COMPONENTS):
            raise optparse.OptionValueError("Запрошен неизвестный компонент: " + component)
        elif component not in parser.values.components:
            #logger.warn("Компонент '%s' уже был исключен.  Не будет произведено никакого действия." % component)
            print("вместо Splunk logger")
        else:
            parser.values.components.remove(component)

    # handle arguments
    # parser = optparse.OptionParser(usage="Usage: splunk diag [options]")
    parser = optparse.OptionParser(usage="Использование: otpdiag [options]")
    # parser.prog = "diag"
    parser.prog = "otpdiag"

    # Добавляем группу опций component_group - компоненты Платформа, которые можно добавить/исключить.
    # В группу добавляем единственную опцию - disable
    component_group = optparse.OptionGroup(parser, "Выбор компонент Платформы",
                      "Параметры определяют, какая диагностическая информация "
                      "должна быть собрана.  Доступны следующие "
                      "компоненты: " + ", ".join(KNOWN_COMPONENTS))

    component_group.add_option("--disable", action="callback", callback=disable_component,
                      nargs=1, type="string", metavar="component_name",
                      help="Исключает компонент из диагностики")

    parser.add_option_group(component_group)


    # output_group параметры - каким образом otp отдаст свои результаты работы
    # --stdout  -  ???  - не разобрался зачем. Пока просто оставил как есть, иначе не работает.
    # Написать заглушку или разобраться
    # -diag-name - имя diag файла. Не закомментировано, но и не используется пока никак ???
    output_group = optparse.OptionGroup(parser, "Output",
                      "These control how diag writes out the result.")

    output_group.add_option("--stdout", action="store_true", dest="stdout",
                      help="Write an uncompressed tar to standard out.  Implies no progress messages.")

    output_group.add_option("--diag-name", "--basename", metavar="name", dest="diagname",
                      help="Задать имя diag-файла. Если параметр не задан, имя будет подготовлено автоматически.")

    parser.add_option_group(output_group)


    # diag-collect every category, except REST, by default
    # no REST for now  because there are too many question marks about reliability
    #default_components = set(KNOWN_COMPONENTS) | set(app_components())
    default_components = set(KNOWN_COMPONENTS) #
    #default_components.remove('rest')
    parser.set_defaults(components=default_components)

    # override above defaults with any from the server.conf file
    #parser.set_defaults(**file_options)

    # Парсим аргументы...
    options, args =  parser.parse_args(cmd_argv)

    return options, args

excluded_filelist = []
# Фильтры  для исключения файлов.
# Пока не используем.

# Основная функция, которая "наполняет" diag
def create_diag(options):
    """ According to the options, create a diag """
    # "Инициализируем" tar для будущего диага
    # initialize whatever is needed for the storage type
    storage.setup(options)

    # Заменяем logger на print
    #logger.info("Starting splunk diag...")
    print("Старт Otp-diag ...")

    # Файл, в который будет собираться системная информация
    sysinfo_filename = None

    try:
        try:
            global system_info
            system_info = tempfile.NamedTemporaryFile(prefix="splunk_sysinfo", mode="w+", delete=False)
            sysinfo_filename = system_info.name
        except IOError:
            '''
            logger.error("Exiting: Cannot create system info file.  Permissions may be wrong.")
            write_logger_buf_on_fail(log_buffer)
            '''
            sys.exit(1)

        # logger.info("Determining diag-launching user...")
        # who is running me?
        systemUsername()

        networkConfig()
        print("Собрали networkConfig...")


    # Завершаем сбор system_info
    finally:
        system_info.close()

    # Добавляем system_info в диаг
    try:
        add_file_to_diag(sysinfo_filename, SYSINFO_FILE)
        print(sysinfo_filename, SYSINFO_FILE)
    finally:
        os.unlink(sysinfo_filename)

    # Создаем и добавляем файл манифеста
    try:
        # Создаем манифест и делаем проверку по эталонному
        exclude_list, otp_home = otphashcheck.create_excl_list("otp")
        manifest_list = otphashcheck.dict_dir(otp_home, exclude_list)
        manifest_file = otp_home + "/ot_diag/manifest.json"
        otphashcheck.save_manifest(manifest_list, manifest_file)
        print(manifest_file)
        add_file_to_diag(manifest_file, manifest_file)
    finally:
        print("Собрали манифест файл платформы...")

    if not 'configs' in options.components:
        # logger.info("Skipping Splunk log files...")
        print("Пропускаем сбор онфигурационных файлов платформы...")
    else:
        # logger.info("Copying Splunk log files...")
        try:
            get_conf(OTP_HOME)
            #add_file_to_diag(file_to_add, filename_in_diag)
            # print(file_to_add, filename_in_diag)
        finally:
            #os.unlink(file_to_add)
            print("Собрали конфигурационные файлы платформы...")

    # Просто пример добавления файла в диаг - убрать или адаптиировать ???


    # storage.complete(options, log_buffer)
    storage.complete()



def main():
    # We want all logged messages to hit our custom in-memory StringIO buffer;
    # but only *SOME* messages to land on the terminal.
    # Что-то про логирование. Пока не реализовано. Закомментировано.
    # log_buffer = logging_horrorshow()

    # --- Извлечение diag-stanza из приложений.
    # Может быть полезно в будущем, если exclude-list будет идти в комплекте с приложением
    # Сейчас не используется и закомментировано.
    # handle options
    # ---

    # hack.. if we're doing --uri, then we don't want to use our locally
    # configured conf file; proper solution is probably to parse arguments
    # first, and then handle file defaults after, I suppose, or to split arg
    # parsing into two phases.
    file_options = {}

    # --- URI используется для сбора "удаленного диага". Формат:
    # Fetch a diag from a remote instance, then upload it
    # $SPLUNK_HOME/bin/splunk diag --uri https://splunkserver.example.com:8089

    # Парсим опции и их аргументы из командной строки запуска
    options, args = local_getopt(file_options)


    # Если задано имя диага через параметр командной строки
    if options.diagname:
        set_diag_name(options.diagname)

    # Создаем tar создаем diag
    try:
        # Obey options? Dump this configurability? TODO
        #set_storage("in_memory")
        #set_storage("directory")

        set_storage("tar")

        # if the rest component is used, or if an app declared it wanted to do
        # rest, then do logins and so on now.

        # Чисто Splunk'овский кусок.
        # Рассмотреть к удалению.
        '''
        if 'rest' in options.components or rest_needed:
            prepare_local_rest_access(options)
            '''

        # Что такое log-buffer пока не известно. Меняем аргументы create_diag - оставляем только options
        '''
        create_diag(options, log_buffer)
        '''
        create_diag(options)


    except Exception as e:
        # Закомментировано все, что связано с логированием
        '''
        logger.error("Exception occurred while generating diag, we are deeply sorry.")
        logger.error(traceback.format_exc())
        # this next line requests a file to be logged, not sure of clearest order
        write_logger_buf_on_fail(log_buffer)
        logger.info("We will now try to clean out any temporary files...")
        '''
        clean_temp_files()
        os.unlink(get_tar_pathname())
        #TODO: pass return value back through clilib
        sys.exit(1)
        #return False

    # and for normal conclusion..
    # Пытаемся очистить временные файлы и докладываем о создании diag
    try:
        #clean up the results dir
        #logger.info("Cleaning up...")
        clean_temp_files()
    finally:
        # Опция statusfile у нас не используется (пока?). Упрощаем.
        '''
        if not options.statusfile: # TODO better way to know if run remotely
            logger.info("Splunk diagnosis file created: %s" % get_tar_pathname())
            '''
        #logger.info("Splunk diagnosis file created: %s" % get_tar_pathname())
        print("Otpdiag создан: %s" % get_tar_pathname())


#######
# direct-run startup, normally splunk diag doesn't use this but
# splunk cmd python info_gather.py goes through here.

if __name__ == "__main__" :
    main()
