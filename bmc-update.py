#!/usr/bin/env python

import argparse
import subprocess
import re
import os
from time import sleep

idracadm    = '/opt/dell/srvadmin/bin/idracadm7'
ipmitool    = '/usr/bin/ipmitool'
smcipmitool = '/opt/smc/SMCIPMITool_2.11.0_bundleJRE_Linux_x64_20140704/SMCIPMITool'
smc_sum     = '/opt/smc/sum_1.4.1_Linux_x86_64/sum'

firmware_info = { 'r720'      : { 'version': '1.66.65', 'path': '/misc/software/dell/drac/firmimg.d7' },
                  'x10drt-pt' : { 'version': '1.94',    'path': '/misc/software/smc/bmc/SMT_X10_194.bin' },
                }

parser = argparse.ArgumentParser()

parser.add_argument('--ip',
                    metavar='IP',
                    help='BMC IP of a server',
                    required=True)

parser.add_argument('--username',
                    metavar='username',
                    help='username',
                    required=True)

parser.add_argument('--password',
                    metavar='password',
                    help='password',
                    required=True)

args = parser.parse_args()

bmc_username = args.username
bmc_password = args.password
bmc_ip = args.ip

def cmd_exec(cmd, tool):
    if tool == 'idrac':
    	cmd = [idracadm,
               '-r',
               bmc_ip,
               '-u',
               bmc_username,
               '-p',
               bmc_password] + cmd.split(' ')
    elif tool == 'ipmitool':
	cmd = [ipmitool,
               '-I',
               'lanplus',
                '-H',
                bmc_ip,
                '-U',
                bmc_username,
                '-P',
                bmc_password] + cmd.split(' ')
    elif tool == 'smcipmitool':
    	cmd = [smcipmitool,
               bmc_ip,
               bmc_username,
               bmc_password] + cmd.split(' ')
    elif tool == 'smc_sum':
	cmd = [smc_sum, 
               '-i',
               bmc_ip,
               '-u',
               bmc_username,
               '-p',
               bmc_password] + cmd.split(' ')
    else:
	raise Exception('This tool is not supported')

    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as error:
        raise Exception(error.output)

def get_hw_info():
    ipmi_fru = cmd_exec('fru print 0', 'ipmitool')
    re_vendor = re.compile('Product Manufacturer.*: (\w+)')

    vendor = re_vendor.findall(ipmi_fru)[0].lower()

    if "dell" in vendor:
	re_model = re.compile('Board Product.*: (.*)')
    elif "supermicro" in vendor:
	re_model = re.compile('Board Part Number.*: (.*)')
    else:
	raise Exception('This hardware is not supported')

    model = re_model.findall(ipmi_fru)[0].lower()
    return vendor, model

def is_host_up():
    timeout = 0 
    while (timeout < 20):
        if subprocess.call(['ping', '-c', '1', bmc_ip], stdout=open(os.devnull, 'wb')) == 0:
            return True
        else:
            timeout+=1
            print('Host is not up, sleep for 30 sec')
            sleep(30)
    
    raise Exception('The host in unreachable')

def is_lc_enabled():
    lc_state = cmd_exec('get lifecyclecontroller.lcattributes.lifecyclecontrollerstate', 'idrac')
    if "Enabled" in lc_state:
        return True
    else:
        return False

def upgrade_dell(model):
    re_r720 = re.compile('poweredge r720.*')
    
    if re_r720.match(model):
        model_short = 'r720'
        last_version = firmware_info[model_short]['version']
        if not os.path.isfile(firmware_info[model_short]['path']):
            raise Exception('Can\'t find firmware file ' + firmware_info[model_short]['path']) 
    else: 
        raise Exception('This hardware is not supported')
     
    current_version = get_firmw_version()
    if current_version != last_version:
        if not is_lc_enabled():
            # set lc value & reboot
            cmd_exec('set lifecyclecontroller.lcattributes.lifecyclecontrollerstate 1', 'idrac')
            cmd_exec('mc reset cold', 'idrac')
            sleep(30)
        
        if is_host_up():
            # do the upgrade
            print('Current version is ' + current_version + '. Upgrading to ' + last_version + '...')
            cmd_exec('update -f ' + firmware_info[model_short]['path'], 'idrac')
            print('Done. Rebooting...')
            sleep(30)
 
        if is_host_up():
            # check if upgrade was successfull
            current_version = get_firmw_version()
            if current_version != last_version:
                raise Exception('Seems like update failed, please check!')
            else: 
                print('Upgrade was done successfully')
                exit(0)
    else:
        print('Upgrade is not required')

def get_firmw_version():
    ipmi_info = cmd_exec('mc info', 'ipmitool')
    return re.compile('Firmware Revision\s+: (.*)').findall(ipmi_info)[0]

def upgrade_supermicro(model):
    re_x10drt_pt = re.compile('x10drt-pt')
    
    if re_x10drt_pt.match(model):
        last_version = firmware_info[model]['version']
        if not os.path.isfile(firmware_info[model]['path']):
            raise Exception('Can\'t find firmware file ' + firmware_info[model]['version'])
    else:
        raise Exception('This hardware is not supported')
    
    current_version = get_firmw_version()
    if current_version != last_version:
        if is_host_up():
            print('Current version is ' + current_version + '. Upgrading to ' + last_version + '...')
            #cmd_exec('ipmi flasha ' + firmware_info[model]['path'] + ' 1', smcipmitool)
            cmd_exec('-c UpdateBmc --file ' + firmware_info[model]['path'], 'smc_sum')
            print('Done. Rebooting...')
            sleep(30)
        if is_host_up():
            current_version = get_firmw_version()
            if current_version != last_version:
                raise Exception('Seems like update failed, please check!')
            else:
                print('Upgrade was done successfully')
                exit(0)
    else:
        print('Upgrade is not required')

def main():
    if is_host_up():
        vendor, model = get_hw_info()

        if 'dell' in vendor:
            upgrade_dell(model)
        elif 'supermicro' in vendor:
            upgrade_supermicro(model)

if __name__ == '__main__':
    main()
