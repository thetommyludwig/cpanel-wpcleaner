#!/usr/bin/python
"""
Author: Tom Ludwig
Date: 02/06/19
About:
    - T2S-II project
    -- https://www.inmotionhosting.com/support/website/wordpress/reinstall-wordpress-after-a-hack
Purpose:
    - provide a means of quickly cleaning wordpress after a hack
Why:
    - address the need to clean hacked sites for clients who request it and refuse sucuri
Actions:
    - downloads the latest wordpress version, creates a clean wp-config.php,
    reinstalls active themes/plugins from wordpress (if they exist) and then copies the
    uploads folder
    -- the only source of previous file hacks would be from uploads which is secured with
    an htaccess block on php/cgi/perl
Requires:
    - root access required and ability to switch user to run wp-cli commands
Issues:
    - may break sites that use a theme or plugin that isn't in wordpress's dashboard
    (since it will not be reinstalled) or if the newest wordpress version isn't
    compatible with a theme or plugin
    - does not address hacks in the database
"""

import sys
import argparse
import subprocess
import os
import shutil
import time
import pwd
import grp
import json
import random
import re
import fileinput
import logging
import string

def get_secure_pass():
    """
    Generate a Memorable and secure password
        5784 words in the list:
        - wordlist is known: password entropy is ~37
        - wordlist isn't known: password entropy is not less than ~56
    """
    try:
        lines = open('wordlist.txt').read().splitlines()
    except IOError as err:
        if "No such file" in str(err):
            logging.info("Wordlist missing: creating key password instead")
            return generate_key()
    else:
        return (random.SystemRandom().choice(lines) + random.SystemRandom().choice(lines) +
                random.SystemRandom().choice(lines))

def shell_enabled(wpc_obj):
    """ Enable shell so we can use wp-cli """
    user = 'user=' + wpc_obj.user
    proc = subprocess.Popen(['whmapi1', 'modifyacct', user, 'HASSHELL=1', \
            'shell=/bin/bash'], stdout=subprocess.PIPE)
    proc.communicate()
    if proc.returncode == 0:
        return True
    else:
        return False

def disable_shell(wpc_obj):
    """ Disable shell by default """
    user = 'user=' + wpc_obj.user
    proc = subprocess.call(['whmapi1', 'modifyacct', user, 'HASSHELL=0'], \
            stdout=subprocess.PIPE)

def subprocess_call(wpc_obj, arg):
    """ Remove clutter of subprocess calls' args """
    arg_list_defaults = [wpc_obj.sudo, '-u', wpc_obj.user, '-i', wpc_obj.php, wpc_obj.wp]
    arg_list = arg_list_defaults + arg
    proc = subprocess.Popen(arg_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, err = proc.communicate()
    return (output, err)

def del_bad_crons(wpc_obj):
    """ Delete cron lines executing perl in tmp """
    cron_path = '/var/spool/cron/' + wpc_obj.user
    pattern = re.compile(r'perl \/var\/tmp\/[a-zA-Z0-9_]+')
    try:
        for line in fileinput.input(cron_path, inplace=True):
            if not re.search(pattern, line):
                print(line.rstrip()) # don't print ^M
    except IOError:
        logging.info("Error opening user's cron file")

def fix_perms(wpc_obj):
    """ Fix permissions/ownership recursively """
    for root, dirs, files in os.walk(wpc_obj.path):
        for directory in dirs:
            os.chmod(os.path.join(root, directory), 0755)
            os.chown(os.path.join(root, directory), wpc_obj.uid, wpc_obj.gid)
        for afile in files:
            os.chmod(os.path.join(root, afile), 0644)
            os.chown(os.path.join(root, afile), wpc_obj.uid, wpc_obj.gid)

def replace_line(file_name, string_match, new_line):
    """ Replace entire line containing string match with new_line """
    already_replaced = False
    for line in fileinput.input(file_name, inplace=True):
        if string_match in line and not already_replaced:
            already_replaced = True
            line = new_line
        print line.rstrip() # remove python adding ^M to every line

def generate_key():
    """ Generate a 65 char string """
    password_characters = string.ascii_letters + string.digits + '!@#$%^&*()'
    return ''.join(random.SystemRandom().choice(password_characters) for i in range(65))

def change_wp_keysalts(wpc_obj):
    """ Invalidate logged in users cookies """
    subprocess_call(wpc_obj, ['config', 'shuffle-salts', wpc_obj.callpath])

def reinstall(wpc_obj):
    """
    Move hacked wordpress document root to inaccessible directory, download
    wordpress, reinstall plugins/themes, and fix permissions
    """
    new_wp_path = wpc_obj.path + '_IMHWPCleanerTMP_' + time.strftime("%Y%m%d-%H%M%S")
    backup_path = wpc_obj.path + '-' + time.strftime("%Y%m%d-%H%M%S") + '.??'
    fix_perms(wpc_obj)
    logging.info("Creating new temp path " + new_wp_path + "...")
    os.mkdir(new_wp_path, 0755)
    gid = grp.getgrnam("nobody").gr_gid
    os.chown(new_wp_path, wpc_obj.uid, gid)
    new_call_path = '--path=' + new_wp_path
    subprocess_call(wpc_obj, ['core', 'download', new_call_path])
    logging.info("Getting list of themes and plugins...")
    json_active_theme, err = subprocess_call(wpc_obj, ['theme', 'list', wpc_obj.callpath, \
                        '--fields=name', '--status=active', '--format=json'])
    json_active_plugins, err = subprocess_call(wpc_obj, ['plugin', 'list', wpc_obj.callpath, \
                                '--status=active', '--format=json'])
    logging.info("Moving hacked document root to " + backup_path)
    shutil.move(wpc_obj.path, backup_path)
    logging.info("Moving new wordpress files into place...")
    shutil.move(new_wp_path, wpc_obj.path)
    logging.info("Copying previous wp-config.php settings...")
    shutil.move(wpc_obj.path + '/wp-config-sample.php', wpc_obj.path + '/wp-config.php')
    with open(backup_path + '/wp-config.php', 'r') as lefile:
        lines = lefile.readlines()
        for line in lines:
            if "DB_NAME" in line:
                replace_line(wpc_obj.path + '/wp-config.php', "DB_NAME", line)
            if "DB_USER" in line:
                replace_line(wpc_obj.path + '/wp-config.php', "DB_USER", line)
            if "DB_PASSWORD" in line:
                replace_line(wpc_obj.path + '/wp-config.php', "DB_PASSWORD", line)
            if "table_prefix" in line:
                replace_line(wpc_obj.path + '/wp-config.php', "table_prefix", line)
    logging.info("Copying uploads directory...")
    if os.path.isdir(backup_path + '/wp-content/uploads'):
        shutil.copytree(backup_path + '/wp-content/uploads', wpc_obj.path + '/wp-content/uploads')
    else:
        logging.info("No uploads folder found, creating...")
        os.mkdir(wpc_obj.path + '/wp-content/uploads', 0755)
    text = '''\n<IfModule mod_rewrite.c> \
            \nRewriteEngine On \
            \nRewriteBase / \
            \nRewriteRule ^index\.php$ - [L] \
            \nRewriteCond %{REQUEST_FILENAME} !-f \
            \nRewriteCond %{REQUEST_FILENAME} !-d \
            \nRewriteRule . /index.php [L] \
            \n</IfModule>'''
    with open(wpc_obj.path + "/.htaccess", 'a+') as lefile:
        lefile.write(text)
    logging.info("Creating .htaccess...")
    open(wpc_obj.path + "/wp-content/uploads/.htaccess", 'w').close()
    logging.info("Fixing permissions...")
    fix_perms(wpc_obj)
    change_wp_keysalts(wpc_obj)
    logging.info("Reinstalling active theme...")
    try:
        theme = (json.loads(json_active_theme))[0]["name"]
    except IndexError:
        #logging.error(e)
        logging.info("No active theme found: activating default...")
        subprocess_call(wpc_obj, ['theme', 'activate', 'twentynineteen', wpc_obj.callpath])
    else:
        theme_installed, err = subprocess_call(wpc_obj, ['theme', 'install', theme, \
                                    wpc_obj.callpath])
        if theme_installed:
            print "Theme " + theme + " reinstalled."
        else:
            logging.info("Could not find theme " + theme + " in wordpress dashboard. \
                            Activating default theme...")
            subprocess_call(wpc_obj, ['theme', 'activate', 'twentynineteen', wpc_obj.callpath])
    logging.info("Reinstalling active plugins...")
    active_plugins = json.loads(json_active_plugins)
    if active_plugins:
        for plugin_dict in active_plugins:
            plugin = plugin_dict["name"]
            logging.info("Installing plugin " + plugin)
            output, err = subprocess_call(wpc_obj, ['plugin', 'install', plugin, wpc_obj.callpath])
            if not output:
                logging.info(plugin + " failed to install.")
    else:
        logging.info("No active plugins.")
    logging.info("Wordpress reinstalled.")

def reinstall_dummy(wpc_obj):
    return

def change_wp_pass(wpc_obj):
    """ Change the admin users' passwords """
    json_admin_users, err = subprocess_call(wpc_obj, ['user', 'list', wpc_obj.callpath, \
                        '--role=administrator', '--format=json', '--fields=ID,user_login'])
    admin_users = json.loads(json_admin_users)
    if admin_users:
        for admin_dict in admin_users:
            password = get_secure_pass()
            user_pass = '--user_pass=' + password
            userid = str(admin_dict["ID"])
            admin = admin_dict["user_login"]
            print("Changing password for " + admin + " with password " +
                    '\x1b[6;30;42m' + password + '\x1b[0m')
            subprocess_call(wpc_obj, ['user', 'update', userid, wpc_obj.callpath, \
                            user_pass, "--skip-email"])
    else:
        logging.info("No admin users found.")

def secure_wp(wpc_obj):
    """
    Make sure wp-uploads doesn't allow php execution and if php handler isn't
    set properly, prevent wp-config.php download
    """
    logging.info("Adding htaccess security blocks...")
    htaccess = wpc_obj.path + "/.htaccess"
    text = '''\n### WPClean ###
            \n<Files "wp-config.php"> \
            \nRequire all denied \
            \n</Files> \
            \n<FilesMatch "^.*\.([Hh][Tt][Aa])"> \
            \nRequire all denied \
            \n</FilesMatch> \
            \n<IfModule mod_rewrite.c> \
            \nRewriteBase / \
            \nRewriteRule ^wp-admin/includes/ - [F,L] \
            \nRewriteRule !^wp-includes/ - [S=3] \
            \nRewriteRule ^wp-includes/[^/]+\.php$ - [F,L] \
            \nRewriteRule ^wp-includes/js/tinymce/langs/.+\.php - [F,L] \
            \nRewriteRule ^wp-includes/theme-compat/ - [F,L]'''
    with open(htaccess, 'a+') as lefile:
        if 'WPClean' not in open(htaccess).read():
            lefile.write(text)
    uploads_htaccess = wpc_obj.path + "/wp-content/uploads/.htaccess"
    text = '''### WPClean ###
            \n<FilesMatch "\.(?:cgi|php|pl)$"> \
            \nDeny from all \
            \n</FilesMatch>'''
    if not os.path.isdir(wpc_obj.path + "/wp-content/uploads"):
        logging.info("Error opening uploads directory")
        os.mkdir(wpc_obj.path + "/wp-content/uploads")
    with open(uploads_htaccess, 'a+') as lefile:
        if 'WPClean' not in open(uploads_htaccess).read():
            lefile.write(text)
    logging.info("Changing wordpress admin users passwords...")
    change_wp_pass(wpc_obj)
    logging.info("Changing wordpress keys and salts...")
    change_wp_keysalts(wpc_obj)
    logging.info("Deleting malicious perl crons...")
    del_bad_crons(wpc_obj)
    logging.info("Fixing permissions...")
    fix_perms(wpc_obj)

def secure_wp_dummy(wpc_obj):
    """ Dummy function for argparse """
    return

def verify_wp(wpc_obj):
    """ Verify wordpress core file checksums """
    logging.info("Verifying wordpress core files...")
    subprocess_call(wpc_obj, ['core', 'verify-checksums', wpc_obj.callpath])

def verify_wp_dummy(wpc_obj):
    """ Dummy function for argparse """
    return

def is_valid_db_conn(wpc_obj):
    """ Check that there's a valid db connection; if not, wp cli fails """
    print "Testing database connection...",
    sys.stdout.flush()
    output, err = subprocess_call(wpc_obj, ['db', 'prefix', wpc_obj.callpath])
    is_conn = bool(len(err) == 0)
    print "Connected" if is_conn else "Not connected\n" + err
    return is_conn

def is_valid_path(path):
    """ Check wp-config.php exists in a home directory """
    print "Checking if path is valid...",
    pattern = re.compile(r'^\/home\/[a-zA-Z0-9_]+(\/[a-zA-Z0-9_])+')
    is_valid = os.path.isdir(path) and re.match(pattern, path) and \
                        os.path.isfile(path + '/wp-config.php')
    print "Valid" if is_valid else "Invalid"
    return is_valid

class Wpcleaner:
    """
    Store OS paths, variables, and check essential binaries/files exist: if not, exit
    """
    def __init__(self, path):
        self.php = self.get_php_path()
        self.sudo = "/usr/bin/sudo"
        self.wp = self.get_wp_path()
        self.path = path.rstrip("/")
        self.callpath = "--path=" + self.path
        self.user = self.get_owner()
        self.gid = self.get_gid()
        self.uid = self.get_uid()

    def get_php_path(self):
        """ Get the path to php binary """
        php_path = (subprocess.Popen(["which", "php"], stdout=subprocess.PIPE)).stdout.read()
        if php_path:
            return php_path
        else:
            sys.exit("PHP is not installed, exiting...")

    def get_wp_path(self):
        """ Get the path to wp-cli """
        wp_path = (subprocess.Popen(["which", "wp"], stdout=subprocess.PIPE)).stdout.read()
        if wp_path:
            return wp_path
        else:
            sys.exit("wp-cli is not installed, exiting...")

    def get_owner(self):
        """ Get the owner """
        try:
            owner = pwd.getpwuid(os.stat(self.path).st_uid).pw_name
        except OSError:
            sys.exit("Error finding owner of path")
        return owner

    def get_uid(self):
        """ Get the UID """
        try:
            uid = os.stat(self.path).st_uid
        except OSError:
            sys.exit("Error finding UID")
        return uid

    def get_gid(self):
        """ Get the GID """
        try:
            gid = pwd.getpwnam(self.user).pw_gid
        except TypeError:
            sys.exit("Error finding group id of user")
        return gid

    def set_log(self):
        """ Create log """
        logdir = '/home/' + self.user + '/.imh'
        logpath = '/home/' + self.user + '/.imh/wpclean.log'
        if not os.path.isdir(logdir):
            os.makedirs(logdir)
        os.chown(logdir, self.uid, self.gid)
        logging.basicConfig(format='%(asctime)s - %(message)s', filename=logpath, \
                            filemode='w+', level=logging.INFO)
        logging.getLogger().addHandler(logging.StreamHandler())
        os.chown(logpath, self.uid, self.gid)

if __name__ == '__main__':
    """
    Parse user's input and call specified functions
    Required:
        - path to the wordpress directory
    Actions:
        - argparse defaults to a dummy function
        - creates a Wpcleaner class object for storing paths and info
        - enable/disable shell
        - calls each provided argument's function
    Checks:
        - path in home directory; a wp-config.php exists; and a valid DB connection
    """
    parser = argparse.ArgumentParser(description='A quick wordpress cleaner \
                                    (Recommended to run with -s)')
    parser.add_argument('-v', '--verify', \
                        action='store_const', \
                        default=verify_wp_dummy, \
                        const=verify_wp, \
                        help='verify wordpress core files')
    parser.add_argument('-s', '--secure', \
                        action='store_const', \
                        default=secure_wp_dummy, \
                        const=secure_wp, \
                        help='security harden wordpress')
    parser.add_argument('-p', '--path', \
                        required=True, \
                        help='path to wordpress files')
    parser.add_argument('-r', '--reinstall', \
                        action='store_const', \
                        default=reinstall_dummy, \
                        const=reinstall, \
                        help='reinstall wordpress')

    args = parser.parse_args()

    if not is_valid_path(args.path):
        print "Error: Invalid path or missing/invalid wp-config.php"
    else:
        wpcleaner_obj = Wpcleaner(args.path)
        if shell_enabled(wpcleaner_obj):
            if is_valid_db_conn(wpcleaner_obj):
                wpcleaner_obj.set_log()
                args.reinstall(wpcleaner_obj)
                args.verify(wpcleaner_obj)
                args.secure(wpcleaner_obj)
                disable_shell(wpcleaner_obj)
            else:
                print "Error: Cannot make a database connection, check wp-config.php settings"
        else:
            print "Error: Unable to enable shell"
