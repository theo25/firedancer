#!/usr/bin/python3

import os
import sys
import argparse
import pathlib
import subprocess
import re

no_input_tests = {
    'test_avx',
    'test_bits',
    'test_compact_u16',
    'test_cstr',
    'test_dcache',
    'test_disco_base',
    'test_ed25519',
    'test_env',
    'test_eth',
    'test_fctl',
    'test_float',
    'test_fseq',
    'test_fxp',
    'test_hash',
    'test_igmp',
    'test_ip4',
    'test_log',
    'test_map',
    'test_map_dynamic',
    'test_mcache',
    'test_pod',
    'test_prq',
    'test_rng',
    'test_scratch',
    'test_set',
    'test_set_dynamic',
    'test_sha512',
    'test_shred',
    'test_smallset',
    'test_sort',
    'test_sqrt',
    'test_sse',
    'test_stat',
    'test_tango_base',
    'test_tempo',
    'test_txn',
    'test_txn',
    'test_txn_parse',
    'test_udp',
    'test_util',
    'test_util_base',
    'test_uwide'
}

numa_tests = {
    'test_replay',
    'test_tcache',
    'test_dedup',
    'test_mux',
    'test_shmem',
    'test_wksp',
    'test_ipc',
    'test_mux_ipc'
}

other_tests = {
    'test_pcap',
    'test_cnc',
    'test_tile'
}

all_unit_tests = no_input_tests.union(numa_tests.union(other_tests))

numa_warning = """The specified unit tests to run include tests that require some shared memory configuration.\n
Run these commands before attempting the tests:
$ sudo bash <fd build dir>/bin/fd_shmem_cfg alloc 1 gigantic 0
$ sudo bash <fd build dir>/bin/fd_shmem_cfg alloc 2 huge 0
$ sudo bash <fd build dir>/bin/fd_shmem_cfg init 700 <user> \"\"\n
If a test fails, you may want to reset the configuration before rerunning:
$ sudo bash <fd build dir>/bin/fd_shmem_cfg reset\n
Run these commands to free the memory when finished:
$ sudo bash <fd build dir>/bin/fd_shmem_cfg fini
$ sudo bash <fd build dir>/bin/fd_shmem_cfg free huge 0
$ sudo bash <fd build dir>/bin/fd_shmem_cfg free gigantic 0\n"""

pass_pattern = re.compile(r'NOTICE .*: pass$')

script_pass_pattern = re.compile(r'pass$')


def run_test(test, test_command, output_dir, time_out=360):
    try:
        stderr_file = output_dir.joinpath(f"{test}.stderr.txt")
        log_file = output_dir.joinpath(f"{test}.log.txt")
        with stderr_file.open(mode='w') as err_fd:
            subprocess.run(
                test_command + ['--log-path', log_file],
                timeout=time_out,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=err_fd)
    except subprocess.TimeoutExpired as to:
        sys.exit(f"Test {test} timed out after {to.timeout} seconds!")
    except subprocess.CalledProcessError as cp:
        sys.exit(f"Test {test} failed: Command {cp.cmd} returned non-zero exit code {cp.returncode}, see logs for more details!")
    except OSError as e:
        sys.exit(f"Test {test} failed: System error with error code {e.errno} and message \'{e.strerror}\'!")

    with stderr_file.open('r') as err_fd:
        if not any(re.match(pass_pattern, line) for line in err_fd):
            sys.exit(f"Test {test} failed, see logs for more details!")


def run_ctl(ctl_command, ctl):
    try:
        subprocess.run(
            ctl_command,
            timeout=360,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired as to:
        sys.exit(f"{ctl} timed out after {to.timeout} seconds!")
    except subprocess.CalledProcessError as cp:
        sys.exit(f"{ctl} failed: Command {cp.cmd} returned non-zero exit code {cp.returncode} !")
    except OSError as e:
        sys.exit(f"{ctl} failed: System error with error code {e.errno} and message \'{e.strerror}\'!")


def run_script(script, script_command, output_dir, time_out=360):
    try:
        stderr_file = output_dir.joinpath(f"{script}.stderr.txt")
        log_file = output_dir.joinpath(f"{script}.log.txt")
        with stderr_file.open(mode='w') as err_fd:
            subprocess.run(
                script_command,
                timeout=time_out,
                check=True,
                stdout=err_fd,
                stderr=subprocess.STDOUT)
    except subprocess.TimeoutExpired as to:
        sys.exit(f"Script {script} timed out after {to.timeout} seconds!")
    except subprocess.CalledProcessError as cp:
        sys.exit(f"Script {script} failed: Command {cp.cmd} returned non-zero exit code {cp.returncode}, see logs for more details!")
    except OSError as e:
        sys.exit(f"Script {script} failed: System error with error code {e.errno} and message \'{e.strerror}\'!")


def run_simple_unit_test(test, test_exe, output_dir):
    print(f"Running test {test} ...")
    run_test(test, [test_exe], output_dir)


def run_shmem_test(test_exe, build_dir, output_dir):
    print(f"Running test test_shmem ...")

    fd_shmem_ctl_bin = build_dir.joinpath('bin', 'fd_shmem_ctl')
    for i in range(3):
        ctl_command = [fd_shmem_ctl_bin, 'create', f"test_shmem_{i}", f"{i+1}", 'normal', '0', '0600']
        run_ctl(ctl_command, 'fd_shmem_ctl')

    test_command = ['taskset', '-c', '14', test_exe, '--tile-cpus', '14', 'test_shmem_0', 'test_shmem_1', 'test_shmem_2']
    run_test('test_shmem', test_command, output_dir)

    ctl_command = [fd_shmem_ctl_bin, 'unlink', 'test_shmem_0', '0', 'unlink', 'test_shmem_1', '0', 'unlink', 'test_shmem_2', '0']
    run_ctl(ctl_command, 'fd_shmem_ctl')


def run_wksp_test(test_exe, build_dir, output_dir):
    print(f"Running test test_wksp ...")

    fd_wksp_ctl_bin = build_dir.joinpath('bin', 'fd_wksp_ctl')
    ctl_command = [fd_wksp_ctl_bin, 'new', 'test_wksp', '1', 'gigantic', '0', '0600']
    run_ctl(ctl_command, 'fd_wksp_ctl')

    test_command = ['taskset', '-c', '16', test_exe, '--wksp', 'test_wksp', '--tile-cpus', '16-22/2']
    run_test('test_wksp', test_command, output_dir, time_out=600)

    ctl_command = [fd_wksp_ctl_bin, 'delete', 'test_wksp']
    run_ctl(ctl_command, 'fd_wksp_ctl')


def run_ipc_test(build_dir, output_dir):
    print(f"Running test test_ipc ...")

    test_exe = build_dir.joinpath('unit-test', 'test_ipc_init')
    if not test_exe.exists():
        sys.exit(f"Executable \'{test_exe}\' for test test_ipc doesn't exist!")
    test_command = ['bash', test_exe, build_dir]
    run_script('test_ipc_init', test_command, output_dir)

    test_exe = build_dir.joinpath('unit-test', 'test_ipc_meta')
    if not test_exe.exists():
        sys.exit(f"Executable \'{test_exe}\' for test test_ipc doesn't exist!")
    test_command = ['bash', test_exe, '16']
    run_script('test_ipc_meta', test_command, output_dir)

    test_exe = build_dir.joinpath('unit-test', 'test_ipc_full')
    if not test_exe.exists():
        sys.exit(f"Executable \'{test_exe}\' for test test_ipc doesn't exist!")
    test_command = ['bash', test_exe, '16']
    run_script('test_ipc_full', test_command, output_dir)

    test_exe = build_dir.joinpath('unit-test', 'test_ipc_fini')
    if not test_exe.exists():
        sys.exit(f"Executable \'{test_exe}\' for test test_ipc doesn't exist!")
    test_command = ['bash', test_exe]
    run_script('test_ipc_fini', test_command, output_dir)


def run_mux_ipc_test(build_dir, output_dir):
    print(f"Running test test_mux_ipc ...")

    test_exe = build_dir.joinpath('unit-test', 'test_mux_ipc_init')
    if not test_exe.exists():
        sys.exit(f"Executable \'{test_exe}\' for test test_mux_ipc doesn't exist!")
    test_command = ['bash', test_exe, build_dir]
    run_script('test_mux_ipc_init', test_command, output_dir)

    #test_exe = build_dir.joinpath('unit-test', 'test_mux_ipc_meta')
    #if not test_exe.exists():
    #    sys.exit(f"Executable \'{test_exe}\' for test test_mux_ipc doesn't exist!")
    #test_command = ['bash', test_exe, '16', '16']
    #run_script('test_mux_ipc_meta', test_command, output_dir)

    #test_exe = build_dir.joinpath('unit-test', 'test_mux_ipc_full')
    #if not test_exe.exists():
    #    sys.exit(f"Executable \'{test_exe}\' for test test_mux_ipc doesn't exist!")
    #test_command = ['bash', test_exe, '16', '16']
    #run_script('test_mux_ipc_full', test_command, output_dir)

    test_exe = build_dir.joinpath('unit-test', 'test_mux_ipc_fini')
    if not test_exe.exists():
        sys.exit(f"Executable \'{test_exe}\' for test test_mux_ipc doesn't exist!")
    test_command = ['bash', test_exe]
    run_script('test_mux_ipc_fini', test_command, output_dir)


def run_pcap_test(test_exe, pcap_file, output_dir):
    print(f"Running test test_pcap ...")

    output_pcap_file = output_dir.joinpath('test_pcap.out.pcap')
    test_command = ['taskset', '-c', '19', test_exe, '--in', pcap_file, '--out', output_pcap_file, '--tile-cpus', '19']
    run_test('test_pcap', test_command, output_dir)


def run_replay_test(test_exe, pcap_file, output_dir):
    print(f"Running test test_replay ...")

    test_command = ['taskset', '-c', '2', test_exe, '--tile-cpus', '2-6/2', '--tx-pcap', pcap_file]
    run_test('test_replay', test_command, output_dir)


def run_cnc_test(test_exe, output_dir):
    print(f"Running test test_cnc ...")

    test_command = ['taskset', '-c', '27', test_exe, '--tile-cpus', '27-29/2']
    run_test('test_cnc', test_command, output_dir)


def run_tile_test(test_exe, output_dir):
    print(f"Running test test_tile ...")

    test_command = ['taskset', '-c', '26', test_exe, '--tile-cpus', '26-30/2']
    run_test('test_tile', test_command, output_dir)


def run_tcache_test(test_exe, output_dir):
    print(f"Running test test_tcache ...")

    test_command = ['taskset', '-c', '2', test_exe, '--tile-cpus', '2']
    run_test('test_tcache', test_command, output_dir)


def run_dedup_test(test_exe, output_dir):
    print(f"Running test test_dedup ...")

    test_command = ['taskset', '-c', '2', test_exe, '--tile-cpus', '2-12/2']
    run_test('test_dedup', test_command, output_dir)


def run_mux_test(test_exe, output_dir):
    print(f"Running test test_mux ...")

    test_command = ['taskset', '-c', '2', test_exe, '--tile-cpus', '2-12/2']
    run_test('test_mux', test_command, output_dir)


def main(arguments):
    parser = argparse.ArgumentParser(
        description='Run the firedancer unit tetst.',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        '-d', '--build-directory',
        help="Directory containing the target firedancer build",
        type=pathlib.Path,
        required=True)
    parser.add_argument(
        '-o', '--output-directory',
        help="Direcotry where logs and output files will be stored",
        type=pathlib.Path,
        required=True)
    parser.add_argument(
        '--pcap',
        help="Ethernet pcap file to be used as input for some unit tests",
        type=pathlib.Path)
    parser.add_argument(
        '--tests',
        help="Unit tests to run, defaults to all unit tests",
        nargs='*',
        choices=all_unit_tests,
        default=list(all_unit_tests))
    parser.add_argument(
        '--except-tests',
        help="Unit tests to skip, defaults to no test",
        nargs='*',
        choices=all_unit_tests,
        default=list())
    parser.add_argument(
        '--no-numa-warning',
        help="Silence the numa warning",
        action='store_true')

    args = parser.parse_args(arguments)

    if not args.build_directory.exists():
        sys.exit(f"Firednacer build path \'{args.build_directory}\' doesn't exist!")

    if not args.build_directory.is_dir():
        sys.exit(f"Firednacer build path \'{args.build_directory}\' is not a directory!")

    build_dir = args.build_directory.resolve()

    if not args.output_directory.exists():
        args.output_directory.mkdir(parents=True)

    if not args.output_directory.is_dir():
        sys.exit(f"Provided output path \'{args.output_directory}\' is not a directory!")

    output_dir = args.output_directory.resolve()

    tests_to_run = set(args.tests).difference(set(args.except_tests))

    if not args.no_numa_warning:
        if any(test in numa_tests for test in tests_to_run):
            print(numa_warning)

    pcap_file = None
    if 'test_pcap' in tests_to_run or 'test_replay' in tests_to_run:
        if not args.pcap:
            sys.exit('No pcap file provided for tests test_pcap and/or test_replay, use flag --pcap to provide one!')
        if not args.pcap.exists():
            sys.exit(f"Provided path to pcap file \'{args.pcap}\' doesn't exist!")
        if not args.pcap.is_file():
            sys.exit(f"Provided path to pcap file \'{args.pcap}\' doesn't point to a file!")
        pcap_file = args.pcap.resolve()

    for test in tests_to_run:
        if test == 'test_ipc':
            run_ipc_test(build_dir, output_dir)
            continue

        if test == 'test_mux_ipc':
            run_mux_ipc_test(build_dir, output_dir)
            continue

        test_exe = build_dir.joinpath('unit-test', test)
        if not test_exe.exists():
            sys.exit(f"Executable \'{test_exe}\' for test {test} doesn't exist!")

        if test in no_input_tests:
            run_simple_unit_test(test, test_exe, output_dir)
        elif test == 'test_shmem':
            run_shmem_test(test_exe, build_dir, output_dir)
        elif test == 'test_wksp':
            run_wksp_test(test_exe, build_dir, output_dir)
        elif test == 'test_pcap':
            run_pcap_test(test_exe, pcap_file, output_dir)
        elif test == 'test_replay':
            run_replay_test(test_exe, pcap_file, output_dir)
        elif test == 'test_cnc':
            run_cnc_test(test_exe, output_dir)
        elif test == 'test_tile':
            run_tile_test(test_exe, output_dir)
        elif test == 'test_tcache':
            run_tcache_test(test_exe, output_dir)
        elif test == 'test_dedup':
            run_dedup_test(test_exe, output_dir)
        elif test == 'test_mux':
            run_mux_test(test_exe, output_dir)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
