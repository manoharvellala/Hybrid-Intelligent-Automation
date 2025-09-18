#!/usr/bin/env python3
"""
Populate STIG rules into PostgreSQL (with JSON references)
"""

import psycopg2
import json

STIG_RULES = [
    
    {
        "id": "xccdf_org.ssgproject.content_rule_gnome_gdm_disable_automatic_login",
        "title": "Disable GDM Automatic Login",
        "severity": "high",
        "description": (
            "The GNOME Display Manager (GDM) can allow users to automatically login "
            "without user interaction or credentials. Users should always be required to "
            "authenticate themselves to the system."
        ),
        "rationale": (
            "Failure to restrict system access to authenticated users negatively impacts "
            "operating system security."
        ),
        "fix": (
            "if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then\n"
            "    if rpm --quiet -q gdm; then\n"
            "        if ! grep -q \"^AutomaticLoginEnable=\" /etc/gdm/custom.conf; then\n"
            "            sed -i \"/^\\[daemon\\]/a \\\n"
            "            AutomaticLoginEnable=False\" /etc/gdm/custom.conf\n"
            "        else\n"
            "            sed -i \"s/^AutomaticLoginEnable=.*/AutomaticLoginEnable=False/g\" /etc/gdm/custom.conf\n"
            "        fi\n"
            "    fi\n"
            "else\n"
            "    >&2 echo 'Remediation is not applicable, nothing was done'\n"
            "fi"
        ),
        "references": {
            "DISA": ["CCI-000366"],
            "NIST": ["CM-6(a)", "AC-6(1)", "CM-7(b)"],
            "STIG-ID": ["RHEL-08-010820"],
            "CCE": ["CCE-80823-8"],
            "stigref": ["SV-230329r1017140_rule"],
            "cis-csc": ["11", "3", "9"],
            "cobit5": ["BAI10.01", "BAI10.02", "BAI10.03", "BAI10.05"],
            "cui": ["3.1.1"],
            "isa-62443-2009": ["4.3.4.3.2", "4.3.4.3.3"],
            "isa-62443-2013": ["SR 7.6"],
            "iso27001-2013": ["A.12.1.2", "A.12.5.1", "A.12.6.2", "A.14.2.2", "A.14.2.3", "A.14.2.4"],
            "nist-csf": ["PR.IP-1"],
            "pcidss4": ["8.3.1", "8.3"],
            "os-srg": ["SRG-OS-000480-GPOS-00229"]
        }
    },

    {
    "id": "xccdf_org.ssgproject.content_rule_disable_ctrlaltdel_burstaction",
    "title": "Disable Ctrl-Alt-Del Burst Action",
    "severity": "high",
    "description": (
        "By default, SystemD will reboot the system if the Ctrl-Alt-Del key sequence is "
        "pressed Ctrl-Alt-Delete more than 7 times in 2 seconds.\n\n"
        "To configure the system to ignore the CtrlAltDelBurstAction setting, add or modify "
        "the following to /etc/systemd/system.conf:\n"
        "CtrlAltDelBurstAction=none"
    ),
    "rationale": (
        "A locally logged-in user who presses Ctrl-Alt-Del, when at the console, can reboot "
        "the system. If accidentally pressed, as could happen in the case of mixed OS environment, "
        "this can create the risk of short-term loss of availability of systems due to unintentional reboot."
    ),
    "fix": (
        "if rpm --quiet -q kernel && { rpm --quiet -q systemd; }; then\n"
        "\n"
        "# Strip any search characters in the key arg so that the key can be replaced without\n"
        "# adding any search characters to the config file.\n"
        "stripped_key=$(sed 's/[\\^=\\$,;+]*//g' <<< \"^CtrlAltDelBurstAction=\")\n"
        "\n"
        "# shellcheck disable=SC2059\n"
        "printf -v formatted_output \"%s=%s\" \"$stripped_key\" \"none\"\n"
        "\n"
        "# If the key exists, change it. Otherwise, add it to the config_file.\n"
        "# We search for the key string followed by a word boundary (matched by \\\\>),\n"
        "# so if we search for 'setting', 'setting2' won't match.\n"
        "if LC_ALL=C grep -q -m 1 -i -e \"^CtrlAltDelBurstAction=\\\\>\" \"/etc/systemd/system.conf\"; then\n"
        "    escaped_formatted_output=$(sed -e 's|/|\\\\/|g' <<< \"$formatted_output\")\n"
        "    LC_ALL=C sed -i --follow-symlinks \"s/^CtrlAltDelBurstAction=\\\\>.*/$escaped_formatted_output/gi\" \"/etc/systemd/system.conf\"\n"
        "else\n"
        "    if [[ -s \"/etc/systemd/system.conf\" ]] && [[ -n \"$(tail -c 1 -- \"/etc/systemd/system.conf\" || true)\" ]]; then\n"
        "        LC_ALL=C sed -i --follow-symlinks '$a'\\\\ \"/etc/systemd/system.conf\"\n"
        "    fi\n"
        "    cce=\"CCE-80784-2\"\n"
        "    printf '# Per %s: Set %s in %s\\n' \"${cce}\" \"${formatted_output}\" \"/etc/systemd/system.conf\" >> \"/etc/systemd/system.conf\"\n"
        "    printf '%s\\n' \"$formatted_output\" >> \"/etc/systemd/system.conf\"\n"
        "fi\n"
        "\n"
        "else\n"
        "    >&2 echo 'Remediation is not applicable, nothing was done'\n"
        "fi"
    ),
    "references": {
        "DISA": ["CCI-000366", "CCI-002235"],
        "NIST": ["CM-6(a)", "AC-6(1)", "CM-6(a)"],
        "STIG-ID": ["RHEL-08-040172"],
        "CCE": ["CCE-80784-2"],
        "stigref": ["SV-230531r1017292_rule"],
        "cis-csc": ["12", "13", "14", "15", "16", "18", "3", "5"],
        "cobit5": ["APO01.06", "DSS05.04", "DSS05.07", "DSS06.02"],
        "cui": ["3.4.5"],
        "hipaa": [
            "164.308(a)(1)(ii)(B)", "164.308(a)(7)(i)", "164.308(a)(7)(ii)(A)", 
            "164.310(a)(1)", "164.310(a)(2)(i)", "164.310(a)(2)(ii)", 
            "164.310(a)(2)(iii)", "164.310(b)", "164.310(c)", 
            "164.310(d)(1)", "164.310(d)(2)(iii)"
        ],
        "isa-62443-2009": ["4.3.3.7.3"],
        "isa-62443-2013": ["SR 2.1", "SR 5.2"],
        "iso27001-2013": [
            "A.10.1.1", "A.11.1.4", "A.11.1.5", "A.11.2.1", "A.13.1.1", "A.13.1.3", "A.13.2.1",
            "A.13.2.3", "A.13.2.4", "A.14.1.2", "A.14.1.3", "A.6.1.2", "A.7.1.1", "A.7.1.2", 
            "A.7.3.1", "A.8.2.2", "A.8.2.3", "A.9.1.1", "A.9.1.2", "A.9.2.3", "A.9.4.1", 
            "A.9.4.4", "A.9.4.5"
        ],
        "nerc-cip": [
            "CIP-003-8 R5.1.1", "CIP-003-8 R5.3", "CIP-004-6 R2.3", "CIP-007-3 R2.1",
            "CIP-007-3 R2.2", "CIP-007-3 R2.3", "CIP-007-3 R5.1", "CIP-007-3 R5.1.1",
            "CIP-007-3 R5.1.2"
        ],
        "nist-csf": ["PR.AC-4", "PR.DS-5"],
        "ospp": ["FAU_GEN.1.2"],
        "os-srg": ["SRG-OS-000324-GPOS-00125", "SRG-OS-000480-GPOS-00227"]
    }
},
{
    "id": "xccdf_org.ssgproject.content_rule_disable_ctrlaltdel_reboot",
    "title": "Disable Ctrl-Alt-Del Reboot Activation",
    "severity": "high",
    "description": (
        "By default, SystemD will reboot the system if the Ctrl-Alt-Del key sequence is pressed.\n\n"
        "To configure the system to ignore the Ctrl-Alt-Del key sequence from the command line instead of "
        "rebooting the system, do either of the following:\n"
        "ln -sf /dev/null /etc/systemd/system/ctrl-alt-del.target\n"
        "or\n"
        "systemctl mask ctrl-alt-del.target\n\n"
        "Do not simply delete the /usr/lib/systemd/system/ctrl-alt-del.service file, "
        "as this file may be restored during future system updates."
    ),
    "rationale": (
        "A locally logged-in user who presses Ctrl-Alt-Del, when at the console, can reboot the system. "
        "If accidentally pressed, as could happen in the case of mixed OS environment, this can create the "
        "risk of short-term loss of availability of systems due to unintentional reboot."
    ),
    "fix": (
        "if rpm --quiet -q kernel; then\n"
        "\n"
        "if [[ \"$OSCAP_BOOTC_BUILD\" == \"YES\" ]] ; then\n"
        "    systemctl disable ctrl-alt-del.target\n"
        "    systemctl mask ctrl-alt-del.target\n"
        "else\n"
        "    systemctl disable --now ctrl-alt-del.target\n"
        "    systemctl mask --now ctrl-alt-del.target\n"
        "fi\n"
        "\n"
        "else\n"
        "    >&2 echo 'Remediation is not applicable, nothing was done'\n"
        "fi"
    ),
    "references": {
        "DISA": ["CCI-000366", "CCI-002235"],
        "NIST": ["CM-6(a)", "AC-6(1)"],
        "STIG-ID": ["RHEL-08-040170"],
        "CCE": ["CCE-80785-9"],
        "stigref": ["SV-230529r1017289_rule"],
        "cis-csc": ["12", "13", "14", "15", "16", "18", "3", "5"],
        "cobit5": ["APO01.06", "DSS05.04", "DSS05.07", "DSS06.02"],
        "cui": ["3.4.5"],
        "hipaa": [
            "164.308(a)(1)(ii)(B)", "164.308(a)(7)(i)", "164.308(a)(7)(ii)(A)",
            "164.310(a)(1)", "164.310(a)(2)(i)", "164.310(a)(2)(ii)", 
            "164.310(a)(2)(iii)", "164.310(b)", "164.310(c)", 
            "164.310(d)(1)", "164.310(d)(2)(iii)"
        ],
        "isa-62443-2009": ["4.3.3.7.3"],
        "isa-62443-2013": ["SR 2.1", "SR 5.2"],
        "iso27001-2013": [
            "A.10.1.1", "A.11.1.4", "A.11.1.5", "A.11.2.1", "A.13.1.1", "A.13.1.3", "A.13.2.1",
            "A.13.2.3", "A.13.2.4", "A.14.1.2", "A.14.1.3", "A.6.1.2", "A.7.1.1", "A.7.1.2", 
            "A.7.3.1", "A.8.2.2", "A.8.2.3", "A.9.1.1", "A.9.1.2", "A.9.2.3", "A.9.4.1", 
            "A.9.4.4", "A.9.4.5"
        ],
        "nerc-cip": [
            "CIP-003-8 R5.1.1", "CIP-003-8 R5.3", "CIP-004-6 R2.3", "CIP-007-3 R2.1",
            "CIP-007-3 R2.2", "CIP-007-3 R2.3", "CIP-007-3 R5.1", "CIP-007-3 R5.1.1",
            "CIP-007-3 R5.1.2"
        ],
        "nist-csf": ["PR.AC-4", "PR.DS-5"],
        "ospp": ["FAU_GEN.1.2"],
        "os-srg": ["SRG-OS-000324-GPOS-00125", "SRG-OS-000480-GPOS-00227"]
    }
},
{
    "id": "xccdf_org.ssgproject.content_rule_accounts_umask_etc_profile",
    "title": "Ensure the Default Umask is Set Correctly in /etc/profile",
    "severity": "medium",
    "description": (
        "To ensure the default umask controlled by /etc/profile is set properly, add or correct the "
        "umask setting in /etc/profile to read as follows:\n"
        "umask 077\n"
        "Note that /etc/profile also reads scripts within /etc/profile.d directory. These scripts are also "
        "valid files to set umask value. Therefore, they should also be considered during the check and "
        "properly remediated, if necessary."
    ),
    "rationale": (
        "The umask value influences the permissions assigned to files when they are created. "
        "A misconfigured umask value could result in files with excessive permissions that can be read "
        "or written to by unauthorized users."
    ),
    "fix": (
        "var_accounts_user_umask='077'\n"
        "\n"
        "readarray -t profile_files < <(find /etc/profile.d/ -type f -name '*.sh' -or -name 'sh.local')\n"
        "\n"
        "for file in \"${profile_files[@]}\" /etc/profile; do\n"
        "  grep -qE '^[^#]*umask' \"$file\" && sed -i -E \"s/^(\\s*umask\\s*)[0-7]+/\\1$var_accounts_user_umask/g\" \"$file\"\n"
        "done\n"
        "\n"
        "if ! grep -qrE '^[^#]*umask' /etc/profile*; then\n"
        "  echo \"umask $var_accounts_user_umask\" >> /etc/profile\n"
        "fi"
    ),
    "references": {
        "DISA": ["CCI-000366"],
        "NIST": ["AC-6(1)", "CM-6(a)"],
        "STIG-ID": ["RHEL-08-020353"],
        "CCE": ["CCE-81035-8"],
        "stigref": ["SV-230385r1017194_rule"],
        "anssi": ["R36"],
        "cis": ["4.5.3.3"],
        "cis-csc": ["18"],
        "cobit5": ["APO13.01", "BAI03.01", "BAI03.02", "BAI03.03"],
        "isa-62443-2009": ["4.3.4.3.3"],
        "iso27001-2013": [
            "A.14.1.1", "A.14.2.1", "A.14.2.5", "A.6.1.5"
        ],
        "nerc-cip": [
            "CIP-003-8 R5.1.1", "CIP-003-8 R5.3", "CIP-004-6 R2.3",
            "CIP-007-3 R2.1", "CIP-007-3 R2.2", "CIP-007-3 R2.3",
            "CIP-007-3 R5.1", "CIP-007-3 R5.1.1", "CIP-007-3 R5.1.2"
        ],
        "nist-csf": ["PR.IP-2"],
        "os-srg": ["SRG-OS-000480-GPOS-00228", "SRG-OS-000480-GPOS-00227"]
    }
},

{
    "id": "xccdf_org.ssgproject.content_rule_mount_option_dev_shm_nodev",
    "title": "Add nodev Option to /dev/shm",
    "severity": "medium",
    "description": (
        "The nodev mount option can be used to prevent creation of device files in /dev/shm. "
        "Legitimate character and block devices should not exist within temporary directories like /dev/shm. "
        "Add the nodev option to the fourth column of /etc/fstab for the line which controls mounting of /dev/shm."
    ),
    "rationale": (
        "The only legitimate location for device files is the /dev directory located on the root partition. "
        "The only exception to this is chroot jails."
    ),
    "fix": (
        "if ( ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && "
        "{ ! rpm --quiet -q openshift-kubelet ;} ) && ! ( [ -f /.dockerenv ] || [ -f /run/.containerenv ] ) ); then\n"
        "\n"
        "function perform_remediation {\n"
        "    mount_point_match_regexp=\"$(printf \"^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]\" /dev/shm)\"\n"
        "\n"
        "    if ! grep -q \"$mount_point_match_regexp\" /etc/fstab; then\n"
        "        previous_mount_opts=$(grep \"$mount_point_match_regexp\" /etc/mtab | head -1 |  awk '{print $4}' \\\n"
        "            | sed -E \"s/(rw|defaults|seclabel|nodev)(,|$)//g;s/,$//\")\n"
        "        [ \"$previous_mount_opts\" ] && previous_mount_opts+=\",\";\n"
        "        fs_type=\"tmpfs\"\n"
        "        if [ \"$fs_type\" == \"iso9660\" ] ; then\n"
        "            previous_mount_opts=$(sed 's/blocksize=/block=/' <<< \"$previous_mount_opts\")\n"
        "        fi\n"
        "        echo \"tmpfs /dev/shm tmpfs defaults,${previous_mount_opts}nodev 0 0\" >> /etc/fstab\n"
        "    elif ! grep \"$mount_point_match_regexp\" /etc/fstab | grep -q \"nodev\"; then\n"
        "        previous_mount_opts=$(grep \"$mount_point_match_regexp\" /etc/fstab | awk '{print $4}')\n"
        "        sed -i \"s|(${mount_point_match_regexp}.*${previous_mount_opts})|\\1,nodev|\" /etc/fstab\n"
        "    fi\n"
        "\n"
        "    if mkdir -p \"/dev/shm\"; then\n"
        "        if mountpoint -q \"/dev/shm\"; then\n"
        "            mount -o remount --target \"/dev/shm\"\n"
        "        fi\n"
        "    fi\n"
        "}\n"
        "perform_remediation\n"
        "\n"
        "else\n"
        "    >&2 echo 'Remediation is not applicable, nothing was done'\n"
        "fi"
    ),
    "references": {
        "DISA": ["CCI-001764"],
        "NIST": ["CM-7(a)", "CM-7(b)", "CM-6(a)", "AC-6", "AC-6(1)", "MP-7"],
        "STIG-ID": ["RHEL-08-040120"],
        "CCE": ["CCE-80837-8"],
        "stigref": ["SV-230508r958804_rule"],
        "cis": ["1.1.2.2.2"],
        "cis-csc": ["11", "13", "14", "3", "8", "9"],
        "cobit5": [
            "APO13.01", "BAI10.01", "BAI10.02", "BAI10.03", "BAI10.05",
            "DSS05.02", "DSS05.05", "DSS05.06", "DSS06.06"
        ],
        "isa-62443-2009": [
            "4.3.3.5.1", "4.3.3.5.2", "4.3.3.5.3", "4.3.3.5.4", "4.3.3.5.5", "4.3.3.5.6", "4.3.3.5.7", "4.3.3.5.8",
            "4.3.3.6.1", "4.3.3.6.2", "4.3.3.6.3", "4.3.3.6.4", "4.3.3.6.5", "4.3.3.6.6", "4.3.3.6.7", "4.3.3.6.8",
            "4.3.3.6.9", "4.3.3.7.1", "4.3.3.7.2", "4.3.3.7.3", "4.3.3.7.4", "4.3.4.3.2", "4.3.4.3.3"
        ],
        "isa-62443-2013": [
            "SR 1.1", "SR 1.10", "SR 1.11", "SR 1.12", "SR 1.13", "SR 1.2", "SR 1.3", "SR 1.4", "SR 1.5", "SR 1.6",
            "SR 1.7", "SR 1.8", "SR 1.9", "SR 2.1", "SR 2.2", "SR 2.3", "SR 2.4", "SR 2.5", "SR 2.6", "SR 2.7", "SR 7.6"
        ],
        "iso27001-2013": [
            "A.11.2.9", "A.12.1.2", "A.12.5.1", "A.12.6.2", "A.14.2.2", "A.14.2.3", "A.14.2.4",
            "A.8.2.1", "A.8.2.2", "A.8.2.3", "A.8.3.1", "A.8.3.3", "A.9.1.2"
        ],
        "nerc-cip": [
            "CIP-003-8 R5.1.1", "CIP-003-8 R5.3", "CIP-004-6 R2.3",
            "CIP-007-3 R2.1", "CIP-007-3 R2.2", "CIP-007-3 R2.3",
            "CIP-007-3 R5.1", "CIP-007-3 R5.1.1", "CIP-007-3 R5.1.2"
        ],
        "nist-csf": ["PR.IP-1", "PR.PT-2", "PR.PT-3"],
        "os-srg": ["SRG-OS-000368-GPOS-00154"]
    }
},










{
  "id": "xccdf_org.ssgproject.content_rule_audit_rules_usergroup_modification_group",
  "title": "Record Events that Modify User/Group Information - /etc/group",
  "severity": "medium",
  "description": (
    "If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following lines to a file with suffix .rules in the directory /etc/audit/rules.d, in order to capture events that modify account changes:\n\n-w /etc/group -p wa -k audit_rules_usergroup_modification\n\n\nIf the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following lines to /etc/audit/audit.rules file, in order to capture events that modify account changes:\n\n-w /etc/group -p wa -k audit_rules_usergroup_modification"
  ),
  "rationale": (
    "In addition to auditing new user and group accounts, these watches will alert the system administrator(s) to any modifications. Any unexpected users, groups, or modifications should be investigated for legitimacy."
  ),
  "fix": (
    "# Remediation is applicable only in certain platforms\nif rpm --quiet -q audit && rpm --quiet -q kernel; then\n\n# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'\n\n# Create a list of audit *.rules files that should be inspected for presence and correctness\n# of a particular audit rule. The scheme is as follows:\n#\n# -----------------------------------------------------------------------------------------\n# Tool used to load audit rules\t| Rule already defined\t|  Audit rules file to inspect\t  |\n# -----------------------------------------------------------------------------------------\n#\tauditctl\t\t|     Doesn't matter\t|  /etc/audit/audit.rules\t  |\n# -----------------------------------------------------------------------------------------\n# \taugenrules\t\t|          Yes\t\t|  /etc/audit/rules.d/*.rules\t  |\n# \taugenrules\t\t|          No\t\t|  /etc/audit/rules.d/$key.rules  |\n# -----------------------------------------------------------------------------------------\nfiles_to_inspect=()\n\n\n# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'\n# into the list of files to be inspected\nfiles_to_inspect+=('/etc/audit/audit.rules')\n\n# Finally perform the inspection and possible subsequent audit rule\n# correction for each of the files previously identified for inspection\nfor audit_rules_file in \"${files_to_inspect[@]}\"\ndo\n    # Check if audit watch file system object rule for given path already present\n    if grep -q -P -- \"^[\\s]*-w[\\s]+/etc/group\" \"$audit_rules_file\"\n    then\n        # Rule is found => verify yet if existing rule definition contains\n        # all of the required access type bits\n\n        # Define BRE whitespace class shortcut\n        sp=\"[[:space:]]\"\n        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule\n        current_access_bits=$(sed -ne \"s#$sp*-w$sp\\+/etc/group $sp\\+-p$sp\\+\\([rxwa]\\{1,4\\}\\).*#\\1#p\" \"$audit_rules_file\")\n        # Split required access bits string into characters array\n        # (to check bit's presence for one bit at a time)\n        for access_bit in $(echo \"wa\" | grep -o .)\n        do\n            # For each from the required access bits (e.g. 'w', 'a') check\n            # if they are already present in current access bits for rule.\n            # If not, append that bit at the end\n            if ! grep -q \"$access_bit\" <<< \"$current_access_bits\"\n            then\n                # Concatenate the existing mask with the missing bit\n                current_access_bits=\"$current_access_bits$access_bit\"\n            fi\n        done\n        # Propagate the updated rule's access bits (original + the required\n        # ones) back into the /etc/audit/audit.rules file for that rule\n        sed -i \"s#\\($sp*-w$sp\\+/etc/group$sp\\+-p$sp\\+\\)\\([rxwa]\\{1,4\\}\\)\\(.*\\)#\\1$current_access_bits\\3#\" \"$audit_rules_file\"\n    else\n        # Rule isn't present yet. Append it at the end of $audit_rules_file file\n        # with proper key\n\n        echo \"-w /etc/group -p wa -k audit_rules_usergroup_modification\" >> \"$audit_rules_file\"\n    fi\ndone\n# Create a list of audit *.rules files that should be inspected for presence and correctness\n# of a particular audit rule. The scheme is as follows:\n#\n# -----------------------------------------------------------------------------------------\n# Tool used to load audit rules\t| Rule already defined\t|  Audit rules file to inspect\t  |\n# -----------------------------------------------------------------------------------------\n#\tauditctl\t\t|     Doesn't matter\t|  /etc/audit/audit.rules\t  |\n# -----------------------------------------------------------------------------------------\n# \taugenrules\t\t|          Yes\t\t|  /etc/audit/rules.d/*.rules\t  |\n# \taugenrules\t\t|          No\t\t|  /etc/audit/rules.d/$key.rules  |\n# -----------------------------------------------------------------------------------------\nfiles_to_inspect=()\n\n# If the audit is 'augenrules', then check if rule is already defined\n# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.\n# If rule isn't defined, add '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' to list of files for inspection.\nreadarray -t matches < <(grep -HP \"[\\s]*-w[\\s]+/etc/group\" /etc/audit/rules.d/*.rules)\n\n# For each of the matched entries\nfor match in \"${matches[@]}\"\ndo\n    # Extract filepath from the match\n    rulesd_audit_file=$(echo $match | cut -f1 -d ':')\n    # Append that path into list of files for inspection\n    files_to_inspect+=(\"$rulesd_audit_file\")\ndone\n# Case when particular audit rule isn't defined yet\nif [ \"${#files_to_inspect[@]}\" -eq \"0\" ]\nthen\n    # Append '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' into list of files for inspection\n    key_rule_file=\"/etc/audit/rules.d/audit_rules_usergroup_modification.rules\"\n    # If the audit_rules_usergroup_modification.rules file doesn't exist yet, create it with correct permissions\n    if [ ! -e \"$key_rule_file\" ]\n    then\n        touch \"$key_rule_file\"\n        chmod 0600 \"$key_rule_file\"\n    fi\n    files_to_inspect+=(\"$key_rule_file\")\nfi\n\n# Finally perform the inspection and possible subsequent audit rule\n# correction for each of the files previously identified for inspection\nfor audit_rules_file in \"${files_to_inspect[@]}\"\ndo\n    # Check if audit watch file system object rule for given path already present\n    if grep -q -P -- \"^[\\s]*-w[\\s]+/etc/group\" \"$audit_rules_file\"\n    then\n        # Rule is found => verify yet if existing rule definition contains\n        # all of the required access type bits\n\n        # Define BRE whitespace class shortcut\n        sp=\"[[:space:]]\"\n        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule\n        current_access_bits=$(sed -ne \"s#$sp*-w$sp\\+/etc/group $sp\\+-p$sp\\+\\([rxwa]\\{1,4\\}\\).*#\\1#p\" \"$audit_rules_file\")\n        # Split required access bits string into characters array\n        # (to check bit's presence for one bit at a time)\n        for access_bit in $(echo \"wa\" | grep -o .)\n        do\n            # For each from the required access bits (e.g. 'w', 'a') check\n            # if they are already present in current access bits for rule.\n            # If not, append that bit at the end\n            if ! grep -q \"$access_bit\" <<< \"$current_access_bits\"\n            then\n                # Concatenate the existing mask with the missing bit\n                current_access_bits=\"$current_access_bits$access_bit\"\n            fi\n        done\n        # Propagate the updated rule's access bits (original + the required\n        # ones) back into the /etc/audit/audit.rules file for that rule\n        sed -i \"s#\\($sp*-w$sp\\+/etc/group$sp\\+-p$sp\\+\\)\\([rxwa]\\{1,4\\}\\)\\(.*\\)#\\1$current_access_bits\\3#\" \"$audit_rules_file\"\n    else\n        # Rule isn't present yet. Append it at the end of $audit_rules_file file\n        # with proper key\n\n        echo \"-w /etc/group -p wa -k audit_rules_usergroup_modification\" >> \"$audit_rules_file\"\n    fi\ndone\n\nelse\n    >&2 echo 'Remediation is not applicable, nothing was done'\nfi"
  ),
  "references": {
    "NIST": ["AC-2(4)", "AU-2(d)", "AU-12(c)", "AC-6(9)", "CM-6(a)"]
  }
},

{
  "id": "xccdf_org.ssgproject.content_rule_audit_rules_usergroup_modification_gshadow",
  "title": "Record Events that Modify User/Group Information - /etc/gshadow",
  "severity": "medium",
  "description": (
    "If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following lines to a file with suffix .rules in the directory /etc/audit/rules.d, in order to capture events that modify account changes:\n\n-w /etc/gshadow -p wa -k audit_rules_usergroup_modification\n\n\nIf the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following lines to /etc/audit/audit.rules file, in order to capture events that modify account changes:\n\n-w /etc/gshadow -p wa -k audit_rules_usergroup_modification"
  ),
  "rationale": (
    "In addition to auditing new user and group accounts, these watches will alert the system administrator(s) to any modifications. Any unexpected users, groups, or modifications should be investigated for legitimacy."
  ),
  "fix": (
    "# Remediation is applicable only in certain platforms\nif rpm --quiet -q audit && rpm --quiet -q kernel; then\n\n# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'\n\n# Create a list of audit *.rules files that should be inspected for presence and correctness\n# of a particular audit rule. The scheme is as follows:\n#\n# -----------------------------------------------------------------------------------------\n# Tool used to load audit rules\t| Rule already defined\t|  Audit rules file to inspect\t  |\n# -----------------------------------------------------------------------------------------\n#\tauditctl\t\t|     Doesn't matter\t|  /etc/audit/audit.rules\t  |\n# -----------------------------------------------------------------------------------------\n# \taugenrules\t\t|          Yes\t\t|  /etc/audit/rules.d/*.rules\t  |\n# \taugenrules\t\t|          No\t\t|  /etc/audit/rules.d/$key.rules  |\n# -----------------------------------------------------------------------------------------\nfiles_to_inspect=()\n\n\n# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'\n# into the list of files to be inspected\nfiles_to_inspect+=('/etc/audit/audit.rules')\n\n# Finally perform the inspection and possible subsequent audit rule\n# correction for each of the files previously identified for inspection\nfor audit_rules_file in \"${files_to_inspect[@]}\"\ndo\n    # Check if audit watch file system object rule for given path already present\n    if grep -q -P -- \"^[\\s]*-w[\\s]+/etc/gshadow\" \"$audit_rules_file\"\n    then\n        # Rule is found => verify yet if existing rule definition contains\n        # all of the required access type bits\n\n        # Define BRE whitespace class shortcut\n        sp=\"[[:space:]]\"\n        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule\n        current_access_bits=$(sed -ne \"s#$sp*-w$sp\\+/etc/gshadow $sp\\+-p$sp\\+\\([rxwa]\\{1,4\\}\\).*#\\1#p\" \"$audit_rules_file\")\n        # Split required access bits string into characters array\n        # (to check bit's presence for one bit at a time)\n        for access_bit in $(echo \"wa\" | grep -o .)\n        do\n            # For each from the required access bits (e.g. 'w', 'a') check\n            # if they are already present in current access bits for rule.\n            # If not, append that bit at the end\n            if ! grep -q \"$access_bit\" <<< \"$current_access_bits\"\n            then\n                # Concatenate the existing mask with the missing bit\n                current_access_bits=\"$current_access_bits$access_bit\"\n            fi\n        done\n        # Propagate the updated rule's access bits (original + the required\n        # ones) back into the /etc/audit/audit.rules file for that rule\n        sed -i \"s#\\($sp*-w$sp\\+/etc/gshadow$sp\\+-p$sp\\+\\)\\([rxwa]\\{1,4\\}\\)\\(.*\\)#\\1$current_access_bits\\3#\" \"$audit_rules_file\"\n    else\n        # Rule isn't present yet. Append it at the end of $audit_rules_file file\n        # with proper key\n\n        echo \"-w /etc/gshadow -p wa -k audit_rules_usergroup_modification\" >> \"$audit_rules_file\"\n    fi\ndone\n# Create a list of audit *.rules files that should be inspected for presence and correctness\n# of a particular audit rule. The scheme is as follows:\n#\n# -----------------------------------------------------------------------------------------\n# Tool used to load audit rules\t| Rule already defined\t|  Audit rules file to inspect\t  |\n# -----------------------------------------------------------------------------------------\n#\tauditctl\t\t|     Doesn't matter\t|  /etc/audit/audit.rules\t  |\n# -----------------------------------------------------------------------------------------\n# \taugenrules\t\t|          Yes\t\t|  /etc/audit/rules.d/*.rules\t  |\n# \taugenrules\t\t|          No\t\t|  /etc/audit/rules.d/$key.rules  |\n# -----------------------------------------------------------------------------------------\nfiles_to_inspect=()\n\n# If the audit is 'augenrules', then check if rule is already defined\n# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.\n# If rule isn't defined, add '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' to list of files for inspection.\nreadarray -t matches < <(grep -HP \"[\\s]*-w[\\s]+/etc/gshadow\" /etc/audit/rules.d/*.rules)\n\n# For each of the matched entries\nfor match in \"${matches[@]}\"\ndo\n    # Extract filepath from the match\n    rulesd_audit_file=$(echo $match | cut -f1 -d ':')\n    # Append that path into list of files for inspection\n    files_to_inspect+=(\"$rulesd_audit_file\")\ndone\n# Case when particular audit rule isn't defined yet\nif [ \"${#files_to_inspect[@]}\" -eq \"0\" ]\nthen\n    # Append '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' into list of files for inspection\n    key_rule_file=\"/etc/audit/rules.d/audit_rules_usergroup_modification.rules\"\n    # If the audit_rules_usergroup_modification.rules file doesn't exist yet, create it with correct permissions\n    if [ ! -e \"$key_rule_file\" ]\n    then\n        touch \"$key_rule_file\"\n        chmod 0600 \"$key_rule_file\"\n    fi\n    files_to_inspect+=(\"$key_rule_file\")\nfi\n\n# Finally perform the inspection and possible subsequent audit rule\n# correction for each of the files previously identified for inspection\nfor audit_rules_file in \"${files_to_inspect[@]}\"\ndo\n    # Check if audit watch file system object rule for given path already present\n    if grep -q -P -- \"^[\\s]*-w[\\s]+/etc/gshadow\" \"$audit_rules_file\"\n    then\n        # Rule is found => verify yet if existing rule definition contains\n        # all of the required access type bits\n\n        # Define BRE whitespace class shortcut\n        sp=\"[[:space:]]\"\n        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule\n        current_access_bits=$(sed -ne \"s#$sp*-w$sp\\+/etc/gshadow $sp\\+-p$sp\\+\\([rxwa]\\{1,4\\}\\).*#\\1#p\" \"$audit_rules_file\")\n        # Split required access bits string into characters array\n        # (to check bit's presence for one bit at a time)\n        for access_bit in $(echo \"wa\" | grep -o .)\n        do\n            # For each from the required access bits (e.g. 'w', 'a') check\n            # if they are already present in current access bits for rule.\n            # If not, append that bit at the end\n            if ! grep -q \"$access_bit\" <<< \"$current_access_bits\"\n            then\n                # Concatenate the existing mask with the missing bit\n                current_access_bits=\"$current_access_bits$access_bit\"\n            fi\n        done\n        # Propagate the updated rule's access bits (original + the required\n        # ones) back into the /etc/audit/audit.rules file for that rule\n        sed -i \"s#\\($sp*-w$sp\\+/etc/gshadow$sp\\+-p$sp\\+\\)\\([rxwa]\\{1,4\\}\\)\\(.*\\)#\\1$current_access_bits\\3#\" \"$audit_rules_file\"\n    else\n        # Rule isn't present yet. Append it at the end of $audit_rules_file file\n        # with proper key\n\n        echo \"-w /etc/gshadow -p wa -k audit_rules_usergroup_modification\" >> \"$audit_rules_file\"\n    fi\ndone\n\nelse\n    >&2 echo 'Remediation is not applicable, nothing was done'\nfi"
  ),
  "references": {
    "NIST": ["AC-2(4)", "AU-2(d)", "AU-12(c)", "AC-6(9)", "CM-6(a)"]
  }
},


{
  "id": "xccdf_org.ssgproject.content_rule_audit_rules_usergroup_modification_opasswd",
  "title": "Record Events that Modify User/Group Information - /etc/security/opasswd",
  "severity": "medium",
  "description": (
    "If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following lines to a file with suffix .rules in the directory /etc/audit/rules.d, in order to capture events that modify account changes:\n\n-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification\n\n\nIf the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following lines to /etc/audit/audit.rules file, in order to capture events that modify account changes:\n\n-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification"
  ),
  "rationale": (
    "In addition to auditing new user and group accounts, these watches will alert the system administrator(s) to any modifications. Any unexpected users, groups, or modifications should be investigated for legitimacy."
  ),
  "fix": (
    "# Remediation is applicable only in certain platforms\nif rpm --quiet -q audit && rpm --quiet -q kernel; then\n\n# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'\n\n# Create a list of audit *.rules files that should be inspected for presence and correctness\n# of a particular audit rule. The scheme is as follows:\n#\n# -----------------------------------------------------------------------------------------\n# Tool used to load audit rules\t| Rule already defined\t|  Audit rules file to inspect\t  |\n# -----------------------------------------------------------------------------------------\n#\tauditctl\t\t|     Doesn't matter\t|  /etc/audit/audit.rules\t  |\n# -----------------------------------------------------------------------------------------\n# \taugenrules\t\t|          Yes\t\t|  /etc/audit/rules.d/*.rules\t  |\n# \taugenrules\t\t|          No\t\t|  /etc/audit/rules.d/$key.rules  |\n# -----------------------------------------------------------------------------------------\nfiles_to_inspect=()\n\n\n# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'\n# into the list of files to be inspected\nfiles_to_inspect+=('/etc/audit/audit.rules')\n\n# Finally perform the inspection and possible subsequent audit rule\n# correction for each of the files previously identified for inspection\nfor audit_rules_file in \"${files_to_inspect[@]}\"\ndo\n    # Check if audit watch file system object rule for given path already present\n    if grep -q -P -- \"^[\\s]*-w[\\s]+/etc/security/opasswd\" \"$audit_rules_file\"\n    then\n        # Rule is found => verify yet if existing rule definition contains\n        # all of the required access type bits\n\n        # Define BRE whitespace class shortcut\n        sp=\"[[:space:]]\"\n        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule\n        current_access_bits=$(sed -ne \"s#$sp*-w$sp\\+/etc/security/opasswd $sp\\+-p$sp\\+\\([rxwa]\\{1,4\\}\\).*#\\1#p\" \"$audit_rules_file\")\n        # Split required access bits string into characters array\n        # (to check bit's presence for one bit at a time)\n        for access_bit in $(echo \"wa\" | grep -o .)\n        do\n            # For each from the required access bits (e.g. 'w', 'a') check\n            # if they are already present in current access bits for rule.\n            # If not, append that bit at the end\n            if ! grep -q \"$access_bit\" <<< \"$current_access_bits\"\n            then\n                # Concatenate the existing mask with the missing bit\n                current_access_bits=\"$current_access_bits$access_bit\"\n            fi\n        done\n        # Propagate the updated rule's access bits (original + the required\n        # ones) back into the /etc/audit/audit.rules file for that rule\n        sed -i \"s#\\($sp*-w$sp\\+/etc/security/opasswd$sp\\+-p$sp\\+\\)\\([rxwa]\\{1,4\\}\\)\\(.*\\)#\\1$current_access_bits\\3#\" \"$audit_rules_file\"\n    else\n        # Rule isn't present yet. Append it at the end of $audit_rules_file file\n        # with proper key\n\n        echo \"-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification\" >> \"$audit_rules_file\"\n    fi\ndone\n# Create a list of audit *.rules files that should be inspected for presence and correctness\n# of a particular audit rule. The scheme is as follows:\n#\n# -----------------------------------------------------------------------------------------\n# Tool used to load audit rules\t| Rule already defined\t|  Audit rules file to inspect\t  |\n# -----------------------------------------------------------------------------------------\n#\tauditctl\t\t|     Doesn't matter\t|  /etc/audit/audit.rules\t  |\n# -----------------------------------------------------------------------------------------\n# \taugenrules\t\t|          Yes\t\t|  /etc/audit/rules.d/*.rules\t  |\n# \taugenrules\t\t|          No\t\t|  /etc/audit/rules.d/$key.rules  |\n# -----------------------------------------------------------------------------------------\nfiles_to_inspect=()\n\n# If the audit is 'augenrules', then check if rule is already defined\n# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.\n# If rule isn't defined, add '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' to list of files for inspection.\nreadarray -t matches < <(grep -HP \"[\\s]*-w[\\s]+/etc/security/opasswd\" /etc/audit/rules.d/*.rules)\n\n# For each of the matched entries\nfor match in \"${matches[@]}\"\ndo\n    # Extract filepath from the match\n    rulesd_audit_file=$(echo $match | cut -f1 -d ':')\n    # Append that path into list of files for inspection\n    files_to_inspect+=(\"$rulesd_audit_file\")\ndone\n# Case when particular audit rule isn't defined yet\nif [ \"${#files_to_inspect[@]}\" -eq \"0\" ]\nthen\n    # Append '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' into list of files for inspection\n    key_rule_file=\"/etc/audit/rules.d/audit_rules_usergroup_modification.rules\"\n    # If the audit_rules_usergroup_modification.rules file doesn't exist yet, create it with correct permissions\n    if [ ! -e \"$key_rule_file\" ]\n    then\n        touch \"$key_rule_file\"\n        chmod 0600 \"$key_rule_file\"\n    fi\n    files_to_inspect+=(\"$key_rule_file\")\nfi\n\n# Finally perform the inspection and possible subsequent audit rule\n# correction for each of the files previously identified for inspection\nfor audit_rules_file in \"${files_to_inspect[@]}\"\ndo\n    # Check if audit watch file system object rule for given path already present\n    if grep -q -P -- \"^[\\s]*-w[\\s]+/etc/security/opasswd\" \"$audit_rules_file\"\n    then\n        # Rule is found => verify yet if existing rule definition contains\n        # all of the required access type bits\n\n        # Define BRE whitespace class shortcut\n        sp=\"[[:space:]]\"\n        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule\n        current_access_bits=$(sed -ne \"s#$sp*-w$sp\\+/etc/security/opasswd $sp\\+-p$sp\\+\\([rxwa]\\{1,4\\}\\).*#\\1#p\" \"$audit_rules_file\")\n        # Split required access bits string into characters array\n        # (to check bit's presence for one bit at a time)\n        for access_bit in $(echo \"wa\" | grep -o .)\n        do\n            # For each from the required access bits (e.g. 'w', 'a') check\n            # if they are already present in current access bits for rule.\n            # If not, append that bit at the end\n            if ! grep -q \"$access_bit\" <<< \"$current_access_bits\"\n            then\n                # Concatenate the existing mask with the missing bit\n                current_access_bits=\"$current_access_bits$access_bit\"\n            fi\n        done\n        # Propagate the updated rule's access bits (original + the required\n        # ones) back into the /etc/audit/audit.rules file for that rule\n        sed -i \"s#\\($sp*-w$sp\\+/etc/security/opasswd$sp\\+-p$sp\\+\\)\\([rxwa]\\{1,4\\}\\)\\(.*\\)#\\1$current_access_bits\\3#\" \"$audit_rules_file\"\n    else\n        # Rule isn't present yet. Append it at the end of $audit_rules_file file\n        # with proper key\n\n        echo \"-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification\" >> \"$audit_rules_file\"\n    fi\ndone\n\nelse\n    >&2 echo 'Remediation is not applicable, nothing was done'\nfi"
  ),
  "references": {
    "NIST": ["AC-2(4)", "AU-2(d)", "AU-12(c)", "AC-6(9)", "CM-6(a)"]
  }
},

{
  "id": "xccdf_org.ssgproject.content_rule_audit_rules_usergroup_modification_passwd",
  "title": "Record Events that Modify User/Group Information - /etc/passwd",
  "severity": "medium",
  "description": (
    "If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following lines to a file with suffix .rules in the directory /etc/audit/rules.d, in order to capture events that modify account changes:\n\n-w /etc/passwd -p wa -k audit_rules_usergroup_modification\n\n\nIf the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following lines to /etc/audit/audit.rules file, in order to capture events that modify account changes:\n\n-w /etc/passwd -p wa -k audit_rules_usergroup_modification"
  ),
  "rationale": (
    "In addition to auditing new user and group accounts, these watches will alert the system administrator(s) to any modifications. Any unexpected users, groups, or modifications should be investigated for legitimacy."
  ),
  "fix": (
    "# Remediation is applicable only in certain platforms\nif rpm --quiet -q audit && rpm --quiet -q kernel; then\n\n# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'\n\n# Create a list of audit *.rules files that should be inspected for presence and correctness\n# of a particular audit rule. The scheme is as follows:\n#\n# -----------------------------------------------------------------------------------------\n# Tool used to load audit rules\t| Rule already defined\t|  Audit rules file to inspect\t  |\n# -----------------------------------------------------------------------------------------\n#\tauditctl\t\t|     Doesn't matter\t|  /etc/audit/audit.rules\t  |\n# -----------------------------------------------------------------------------------------\n# \taugenrules\t\t|          Yes\t\t|  /etc/audit/rules.d/*.rules\t  |\n# \taugenrules\t\t|          No\t\t|  /etc/audit/rules.d/$key.rules  |\n# -----------------------------------------------------------------------------------------\nfiles_to_inspect=()\n\n\n# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'\n# into the list of files to be inspected\nfiles_to_inspect+=('/etc/audit/audit.rules')\n\n# Finally perform the inspection and possible subsequent audit rule\n# correction for each of the files previously identified for inspection\nfor audit_rules_file in \"${files_to_inspect[@]}\"\ndo\n    # Check if audit watch file system object rule for given path already present\n    if grep -q -P -- \"^[\\s]*-w[\\s]+/etc/passwd\" \"$audit_rules_file\"\n    then\n        # Rule is found => verify yet if existing rule definition contains\n        # all of the required access type bits\n\n        # Define BRE whitespace class shortcut\n        sp=\"[[:space:]]\"\n        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule\n        current_access_bits=$(sed -ne \"s#$sp*-w$sp\\+/etc/passwd $sp\\+-p$sp\\+\\([rxwa]\\{1,4\\}\\).*#\\1#p\" \"$audit_rules_file\")\n        # Split required access bits string into characters array\n        # (to check bit's presence for one bit at a time)\n        for access_bit in $(echo \"wa\" | grep -o .)\n        do\n            # For each from the required access bits (e.g. 'w', 'a') check\n            # if they are already present in current access bits for rule.\n            # If not, append that bit at the end\n            if ! grep -q \"$access_bit\" <<< \"$current_access_bits\"\n            then\n                # Concatenate the existing mask with the missing bit\n                current_access_bits=\"$current_access_bits$access_bit\"\n            fi\n        done\n        # Propagate the updated rule's access bits (original + the required\n        # ones) back into the /etc/audit/audit.rules file for that rule\n        sed -i \"s#\\($sp*-w$sp\\+/etc/passwd$sp\\+-p$sp\\+\\)\\([rxwa]\\{1,4\\}\\)\\(.*\\)#\\1$current_access_bits\\3#\" \"$audit_rules_file\"\n    else\n        # Rule isn't present yet. Append it at the end of $audit_rules_file file\n        # with proper key\n\n        echo \"-w /etc/passwd -p wa -k audit_rules_usergroup_modification\" >> \"$audit_rules_file\"\n    fi\ndone\n# Create a list of audit *.rules files that should be inspected for presence and correctness\n# of a particular audit rule. The scheme is as follows:\n#\n# -----------------------------------------------------------------------------------------\n# Tool used to load audit rules\t| Rule already defined\t|  Audit rules file to inspect\t  |\n# -----------------------------------------------------------------------------------------\n#\tauditctl\t\t|     Doesn't matter\t|  /etc/audit/audit.rules\t  |\n# -----------------------------------------------------------------------------------------\n# \taugenrules\t\t|          Yes\t\t|  /etc/audit/rules.d/*.rules\t  |\n# \taugenrules\t\t|          No\t\t|  /etc/audit/rules.d/$key.rules  |\n# -----------------------------------------------------------------------------------------\nfiles_to_inspect=()\n\n# If the audit is 'augenrules', then check if rule is already defined\n# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.\n# If rule isn't defined, add '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' to list of files for inspection.\nreadarray -t matches < <(grep -HP \"[\\s]*-w[\\s]+/etc/passwd\" /etc/audit/rules.d/*.rules)\n\n# For each of the matched entries\nfor match in \"${matches[@]}\"\ndo\n    # Extract filepath from the match\n    rulesd_audit_file=$(echo $match | cut -f1 -d ':')\n    # Append that path into list of files for inspection\n    files_to_inspect+=(\"$rulesd_audit_file\")\ndone\n# Case when particular audit rule isn't defined yet\nif [ \"${#files_to_inspect[@]}\" -eq \"0\" ]\nthen\n    # Append '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' into list of files for inspection\n    key_rule_file=\"/etc/audit/rules.d/audit_rules_usergroup_modification.rules\"\n    # If the audit_rules_usergroup_modification.rules file doesn't exist yet, create it with correct permissions\n    if [ ! -e \"$key_rule_file\" ]\n    then\n        touch \"$key_rule_file\"\n        chmod 0600 \"$key_rule_file\"\n    fi\n    files_to_inspect+=(\"$key_rule_file\")\nfi\n\n# Finally perform the inspection and possible subsequent audit rule\n# correction for each of the files previously identified for inspection\nfor audit_rules_file in \"${files_to_inspect[@]}\"\ndo\n    # Check if audit watch file system object rule for given path already present\n    if grep -q -P -- \"^[\\s]*-w[\\s]+/etc/passwd\" \"$audit_rules_file\"\n    then\n        # Rule is found => verify yet if existing rule definition contains\n        # all of the required access type bits\n\n        # Define BRE whitespace class shortcut\n        sp=\"[[:space:]]\"\n        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule\n        current_access_bits=$(sed -ne \"s#$sp*-w$sp\\+/etc/passwd $sp\\+-p$sp\\+\\([rxwa]\\{1,4\\}\\).*#\\1#p\" \"$audit_rules_file\")\n        # Split required access bits string into characters array\n        # (to check bit's presence for one bit at a time)\n        for access_bit in $(echo \"wa\" | grep -o .)\n        do\n            # For each from the required access bits (e.g. 'w', 'a') check\n            # if they are already present in current access bits for rule.\n            # If not, append that bit at the end\n            if ! grep -q \"$access_bit\" <<< \"$current_access_bits\"\n            then\n                # Concatenate the existing mask with the missing bit\n                current_access_bits=\"$current_access_bits$access_bit\"\n            fi\n        done\n        # Propagate the updated rule's access bits (original + the required\n        # ones) back into the /etc/audit/audit.rules file for that rule\n        sed -i \"s#\\($sp*-w$sp\\+/etc/passwd$sp\\+-p$sp\\+\\)\\([rxwa]\\{1,4\\}\\)\\(.*\\)#\\1$current_access_bits\\3#\" \"$audit_rules_file\"\n    else\n        # Rule isn't present yet. Append it at the end of $audit_rules_file file\n        # with proper key\n\n        echo \"-w /etc/passwd -p wa -k audit_rules_usergroup_modification\" >> \"$audit_rules_file\"\n    fi\ndone\n\nelse\n    >&2 echo 'Remediation is not applicable, nothing was done'\nfi"
  ),
  "references": {
    "NIST": ["AC-2(4)", "AU-2(d)", "AU-12(c)", "AC-6(9)", "CM-6(a)"]
  }
},


{
  "id": "xccdf_org.ssgproject.content_rule_audit_rules_usergroup_modification_shadow",
  "title": "Record Events that Modify User/Group Information - /etc/shadow",
  "severity": "medium",
  "description": (
    "If the auditd daemon is configured to use the augenrules program to read audit rules during daemon startup (the default), add the following lines to a file with suffix .rules in the directory /etc/audit/rules.d, in order to capture events that modify account changes:\n\n-w /etc/shadow -p wa -k audit_rules_usergroup_modification\n\n\nIf the auditd daemon is configured to use the auditctl utility to read audit rules during daemon startup, add the following lines to /etc/audit/audit.rules file, in order to capture events that modify account changes:\n\n-w /etc/shadow -p wa -k audit_rules_usergroup_modification"
  ),
  "rationale": (
    "In addition to auditing new user and group accounts, these watches will alert the system administrator(s) to any modifications. Any unexpected users, groups, or modifications should be investigated for legitimacy."
  ),
  "fix": (
    "# Remediation is applicable only in certain platforms\nif rpm --quiet -q audit && rpm --quiet -q kernel; then\n\n# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'\n\n# Create a list of audit *.rules files that should be inspected for presence and correctness\n# of a particular audit rule. The scheme is as follows:\n#\n# -----------------------------------------------------------------------------------------\n# Tool used to load audit rules\t| Rule already defined\t|  Audit rules file to inspect\t  |\n# -----------------------------------------------------------------------------------------\n#\tauditctl\t\t|     Doesn't matter\t|  /etc/audit/audit.rules\t  |\n# -----------------------------------------------------------------------------------------\n# \taugenrules\t\t|          Yes\t\t|  /etc/audit/rules.d/*.rules\t  |\n# \taugenrules\t\t|          No\t\t|  /etc/audit/rules.d/$key.rules  |\n# -----------------------------------------------------------------------------------------\nfiles_to_inspect=()\n\n\n# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'\n# into the list of files to be inspected\nfiles_to_inspect+=('/etc/audit/audit.rules')\n\n# Finally perform the inspection and possible subsequent audit rule\n# correction for each of the files previously identified for inspection\nfor audit_rules_file in \"${files_to_inspect[@]}\"\ndo\n    # Check if audit watch file system object rule for given path already present\n    if grep -q -P -- \"^[\\s]*-w[\\s]+/etc/shadow\" \"$audit_rules_file\"\n    then\n        # Rule is found => verify yet if existing rule definition contains\n        # all of the required access type bits\n\n        # Define BRE whitespace class shortcut\n        sp=\"[[:space:]]\"\n        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule\n        current_access_bits=$(sed -ne \"s#$sp*-w$sp\\+/etc/shadow $sp\\+-p$sp\\+\\([rxwa]\\{1,4\\}\\).*#\\1#p\" \"$audit_rules_file\")\n        # Split required access bits string into characters array\n        # (to check bit's presence for one bit at a time)\n        for access_bit in $(echo \"wa\" | grep -o .)\n        do\n            # For each from the required access bits (e.g. 'w', 'a') check\n            # if they are already present in current access bits for rule.\n            # If not, append that bit at the end\n            if ! grep -q \"$access_bit\" <<< \"$current_access_bits\"\n            then\n                # Concatenate the existing mask with the missing bit\n                current_access_bits=\"$current_access_bits$access_bit\"\n            fi\n        done\n        # Propagate the updated rule's access bits (original + the required\n        # ones) back into the /etc/audit/audit.rules file for that rule\n        sed -i \"s#\\($sp*-w$sp\\+/etc/shadow$sp\\+-p$sp\\+\\)\\([rxwa]\\{1,4\\}\\)\\(.*\\)#\\1$current_access_bits\\3#\" \"$audit_rules_file\"\n    else\n        # Rule isn't present yet. Append it at the end of $audit_rules_file file\n        # with proper key\n\n        echo \"-w /etc/shadow -p wa -k audit_rules_usergroup_modification\" >> \"$audit_rules_file\"\n    fi\ndone\n# Create a list of audit *.rules files that should be inspected for presence and correctness\n# of a particular audit rule. The scheme is as follows:\n#\n# -----------------------------------------------------------------------------------------\n# Tool used to load audit rules\t| Rule already defined\t|  Audit rules file to inspect\t  |\n# -----------------------------------------------------------------------------------------\n#\tauditctl\t\t|     Doesn't matter\t|  /etc/audit/audit.rules\t  |\n# -----------------------------------------------------------------------------------------\n# \taugenrules\t\t|          Yes\t\t|  /etc/audit/rules.d/*.rules\t  |\n# \taugenrules\t\t|          No\t\t|  /etc/audit/rules.d/$key.rules  |\n# -----------------------------------------------------------------------------------------\nfiles_to_inspect=()\n\n# If the audit is 'augenrules', then check if rule is already defined\n# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.\n# If rule isn't defined, add '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' to list of files for inspection.\nreadarray -t matches < <(grep -HP \"[\\s]*-w[\\s]+/etc/shadow\" /etc/audit/rules.d/*.rules)\n\n# For each of the matched entries\nfor match in \"${matches[@]}\"\ndo\n    # Extract filepath from the match\n    rulesd_audit_file=$(echo $match | cut -f1 -d ':')\n    # Append that path into list of files for inspection\n    files_to_inspect+=(\"$rulesd_audit_file\")\ndone\n# Case when particular audit rule isn't defined yet\nif [ \"${#files_to_inspect[@]}\" -eq \"0\" ]\nthen\n    # Append '/etc/audit/rules.d/audit_rules_usergroup_modification.rules' into list of files for inspection\n    key_rule_file=\"/etc/audit/rules.d/audit_rules_usergroup_modification.rules\"\n    # If the audit_rules_usergroup_modification.rules file doesn't exist yet, create it with correct permissions\n    if [ ! -e \"$key_rule_file\" ]\n    then\n        touch \"$key_rule_file\"\n        chmod 0600 \"$key_rule_file\"\n    fi\n    files_to_inspect+=(\"$key_rule_file\")\nfi\n\n# Finally perform the inspection and possible subsequent audit rule\n# correction for each of the files previously identified for inspection\nfor audit_rules_file in \"${files_to_inspect[@]}\"\ndo\n    # Check if audit watch file system object rule for given path already present\n    if grep -q -P -- \"^[\\s]*-w[\\s]+/etc/shadow\" \"$audit_rules_file\"\n    then\n        # Rule is found => verify yet if existing rule definition contains\n        # all of the required access type bits\n\n        # Define BRE whitespace class shortcut\n        sp=\"[[:space:]]\"\n        # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule\n        current_access_bits=$(sed -ne \"s#$sp*-w$sp\\+/etc/shadow $sp\\+-p$sp\\+\\([rxwa]\\{1,4\\}\\).*#\\1#p\" \"$audit_rules_file\")\n        # Split required access bits string into characters array\n        # (to check bit's presence for one bit at a time)\n        for access_bit in $(echo \"wa\" | grep -o .)\n        do\n            # For each from the required access bits (e.g. 'w', 'a') check\n            # if they are already present in current access bits for rule.\n            # If not, append that bit at the end\n            if ! grep -q \"$access_bit\" <<< \"$current_access_bits\"\n            then\n                # Concatenate the existing mask with the missing bit\n                current_access_bits=\"$current_access_bits$access_bit\"\n            fi\n        done\n        # Propagate the updated rule's access bits (original + the required\n        # ones) back into the /etc/audit/audit.rules file for that rule\n        sed -i \"s#\\($sp*-w$sp\\+/etc/shadow$sp\\+-p$sp\\+\\)\\([rxwa]\\{1,4\\}\\)\\(.*\\)#\\1$current_access_bits\\3#\" \"$audit_rules_file\"\n    else\n        # Rule isn't present yet. Append it at the end of $audit_rules_file file\n        # with proper key\n\n        echo \"-w /etc/shadow -p wa -k audit_rules_usergroup_modification\" >> \"$audit_rules_file\"\n    fi\ndone\n\nelse\n    >&2 echo 'Remediation is not applicable, nothing was done'\nfi"
  ),
  "references": {
    "NIST": ["AC-2(4)", "AU-2(d)", "AU-12(c)", "AC-6(9)", "CM-6(a)"]
  }
},

{
  "id": "xccdf_org.ssgproject.content_rule_account_disable_post_pw_expiration",
  "title": "Set Account Expiration Following Inactivity",
  "severity": "medium",
  "description": (
    "To specify the number of days after a password expires (which signifies inactivity) until an account is permanently disabled, add or correct the following line in /etc/default/useradd:\nINACTIVE=35\nIf a password is currently on the verge of expiration, then 35 day(s) remain(s) until the account is automatically disabled. However, if the password will not expire for another 60 days, then 60 days plus 35 day(s) could elapse until the account would be automatically disabled. See the useradd man page for more information."
  ),
  "rationale": (
    "Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Disabling inactive accounts ensures that accounts which may not have been responsibly removed are not available to attackers who may have compromised their credentials. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained."
  ),
  "fix": (
    "# Remediation is applicable only in certain platforms\nif rpm --quiet -q shadow-utils; then\n\nvar_account_disable_post_pw_expiration='35'\n\n\n# Strip any search characters in the key arg so that the key can be replaced without\n# adding any search characters to the config file.\nstripped_key=$(sed 's/[\\^=\\$,;+]*//g' <<< \"^INACTIVE\")\n\n# shellcheck disable=SC2059\nprintf -v formatted_output \"%s=%s\" \"$stripped_key\" \"$var_account_disable_post_pw_expiration\"\n\n# If the key exists, change it. Otherwise, add it to the config_file.\n# We search for the key string followed by a word boundary (matched by \\>),\n# so if we search for 'setting', 'setting2' won't match.\nif LC_ALL=C grep -q -m 1 -i -e \"^INACTIVE\\\\>\" \"/etc/default/useradd\"; then\n    escaped_formatted_output=$(sed -e 's|/|\\\\/|g' <<< \"$formatted_output\")\n    LC_ALL=C sed -i --follow-symlinks \"s/^INACTIVE\\\\>.*/$formatted_output/gi\" \"/etc/default/useradd\"\nelse\n    if [[ -s \"/etc/default/useradd\" ]] && [[ -n \"$(tail -c 1 -- \"/etc/default/useradd\" || true)\" ]]; then\n        LC_ALL=C sed -i --follow-symlinks '$a'\\\\ \"/etc/default/useradd\"\n    fi\n    cce=\"CCE-80954-1\"\n    printf '# Per %s: Set %s in %s\\n' \"${cce}\" \"${formatted_output}\" \"/etc/default/useradd\" >> \"/etc/default/useradd\"\n    printf '%s\\n' \"$formatted_output\" >> \"/etc/default/useradd\"\nfi\n\nelse\n    >&2 echo 'Remediation is not applicable, nothing was done'\nfi"
  ),
  "references": {
    "NIST": ["IA-4(e)", "AC-2(3)", "CM-6(a)"]
  }
},

{
  "id": "xccdf_org.ssgproject.content_rule_logind_session_timeout",
  "title": "Configure Logind to terminate idle sessions after certain time of inactivity",
  "severity": "medium",
  "description": (
    "To configure logind service to terminate inactive user sessions after 600 seconds, edit the file /etc/systemd/logind.conf. Ensure that there is a section\n[Login]\nwhich contains the configuration\nStopIdleSessionSec=600\n."
  ),
  "rationale": (
    "Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been let unattended."
  ),
  "fix": (
    "# Remediation is applicable only in certain platforms\nif rpm --quiet -q kernel && { ( grep -qP \"^ID=[\\\"']?rhel[\\\"']?$\" \"/etc/os-release\" && { real=\"$(grep -P \"^VERSION_ID=[\\\"']?[\\w.]+[\\\"']?$\" /etc/os-release | sed \"s/^VERSION_ID=[\\\"']\\?\\([^\\\"']\\+\\)[\\\"']\\?$/\\1/\")\"; expected=\"8.7\"; printf \"%s\\n%s\" \"$expected\" \"$real\" | sort -VC; } && grep -qP \"^ID=[\\\"']?rhel[\\\"']?$\" \"/etc/os-release\" && { real=\"$(grep -P \"^VERSION_ID=[\\\"']?[\\w.]+[\\\"']?$\" /etc/os-release | sed \"s/^VERSION_ID=[\\\"']\\?\\([^\\\"']\\+\\)[\\\"']\\?$/\\1/\")\"; expected=\"9.0\"; [[ \"$real\" != \"$expected\" ]]; } ) || grep -qP \"^ID=[\\\"']?ol[\\\"']?$\" \"/etc/os-release\" && { real=\"$(grep -P \"^VERSION_ID=[\\\"']?[\\w.]+[\\\"']?$\" /etc/os-release | sed \"s/^VERSION_ID=[\\\"']\\?\\([^\\\"']\\+\\)[\\\"']\\?$/\\1/\")\"; expected=\"8.7\"; printf \"%s\\n%s\" \"$expected\" \"$real\" | sort -VC; }; }; then\n\nvar_logind_session_timeout='600'\n\n\n\n# Try find '[Login]' and 'StopIdleSessionSec' in '/etc/systemd/logind.conf', if it exists, set\n# to '$var_logind_session_timeout', if it isn't here, add it, if '[Login]' doesn't exist, add it there\nif grep -qzosP '[[:space:]]*\\[Login]([^\\n\\[]*\\n+)+?[[:space:]]*StopIdleSessionSec' '/etc/systemd/logind.conf'; then\n    \n    sed -i \"s/StopIdleSessionSec^[^(]*[(]?[\\n]?[)]*\\/StopIdleSessionSec=$var_logind_session_timeout/\" '/etc/systemd/logind.conf'\nelif grep -qs '[[:space:]]*\\[Login]' '/etc/systemd/logind.conf'; then\n    sed -i \"/[[:space:]]*\\[Login]/a StopIdleSessionSec=$var_logind_session_timeout\" '/etc/systemd/logind.conf'\nelse\n    if test -d \"/etc/systemd\"; then\n        printf '%s\\n' '[Login]' \"StopIdleSessionSec=$var_logind_session_timeout\" >> '/etc/systemd/logind.conf'\n    else\n        echo \"Config file directory '/etc/systemd' doesnt exist, not remediating, assuming non-applicability.\" >&2\n    fi\nfi\n\nelse\n    >&2 echo 'Remediation is not applicable, nothing was done'\nfi"
  ),
  "references": {
    "NIST": ["CM-6(a)", "AC-17(a)", "AC-2(5)", "AC-12", "AC-17(a)", "SC-10", "CM-6(a)"]
  }
},

{
  "id": "xccdf_org.ssgproject.content_rule_sshd_set_keepalive",
  "title": "Set SSH Client Alive Count Max",
  "severity": "medium",
  "description": (
    "The SSH server sends at most ClientAliveCountMax messages during a SSH session and waits for a response from the SSH client. The option ClientAliveInterval configures timeout after each ClientAliveCountMax message. If the SSH server does not receive a response from the client, then the connection is considered unresponsive and terminated. For SSH earlier than v8.2, a ClientAliveCountMax value of 0 causes a timeout precisely when the ClientAliveInterval is set. Starting with v8.2, a value of 0 disables the timeout functionality completely. If the option is set to a number greater than 0, then the session will be disconnected after ClientAliveInterval * ClientAliveCountMax seconds without receiving a keep alive message."
  ),
  "rationale": (
    "This ensures a user login will be terminated as soon as the ClientAliveInterval is reached."
  ),
  "fix": (
    "# Remediation is applicable only in certain platforms\nif rpm --quiet -q kernel; then\n\nvar_sshd_set_keepalive='1'\n\n\n\nif [ -e \"/etc/ssh/sshd_config\" ] ; then\n    \n    LC_ALL=C sed -i \"/^\\s*ClientAliveCountMax\\s\\+/Id\" \"/etc/ssh/sshd_config\"\nelse\n    touch \"/etc/ssh/sshd_config\"\nfi\n# make sure file has newline at the end\nsed -i -e '$a\\' \"/etc/ssh/sshd_config\"\n\ncp \"/etc/ssh/sshd_config\" \"/etc/ssh/sshd_config.bak\"\n# Insert at the beginning of the file\nprintf '%s\\n' \"ClientAliveCountMax $var_sshd_set_keepalive\" > \"/etc/ssh/sshd_config\"\ncat \"/etc/ssh/sshd_config.bak\" >> \"/etc/ssh/sshd_config\"\n# Clean up after ourselves.\nrm \"/etc/ssh/sshd_config.bak\"\n\nelse\n    >&2 echo 'Remediation is not applicable, nothing was done'\nfi"
  ),
  "references": {
    "NIST": ["AC-2(5)", "AC-12", "AC-17(a)", "SC-10", "CM-6(a)"]
  }
},

{
  "id": "xccdf_org.ssgproject.content_rule_sshd_set_idle_timeout",
  "title": "Set SSH Client Alive Interval",
  "severity": "medium",
  "description": (
    "SSH allows administrators to set a network responsiveness timeout interval. After this interval has passed, the unresponsive client will be automatically logged out.\n\nTo set this timeout interval, edit the following line in /etc/ssh/sshd_config as follows:\nClientAliveInterval 600\n\n\nThe timeout interval is given in seconds. For example, have a timeout of 10 minutes, set interval to 600.\n\nIf a shorter timeout has already been set for the login shell, that value will preempt any SSH setting made in /etc/ssh/sshd_config. Keep in mind that some processes may stop SSH from correctly detecting that the user is idle."
  ),
  "rationale": (
    "Terminating an idle ssh session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been let unattended."
  ),
  "fix": (
    "# Remediation is applicable only in certain platforms\nif rpm --quiet -q kernel; then\n\nsshd_idle_timeout_value='600'\n\n\n\nif [ -e \"/etc/ssh/sshd_config\" ] ; then\n    \n    LC_ALL=C sed -i \"/^\\s*ClientAliveInterval\\s\\+/Id\" \"/etc/ssh/sshd_config\"\nelse\n    touch \"/etc/ssh/sshd_config\"\nfi\n# make sure file has newline at the end\nsed -i -e '$a\\' \"/etc/ssh/sshd_config\"\n\ncp \"/etc/ssh/sshd_config\" \"/etc/ssh/sshd_config.bak\"\n# Insert at the beginning of the file\nprintf '%s\\n' \"ClientAliveInterval $sshd_idle_timeout_value\" > \"/etc/ssh/sshd_config\"\ncat \"/etc/ssh/sshd_config.bak\" >> \"/etc/ssh/sshd_config\"\n# Clean up after ourselves.\nrm \"/etc/ssh/sshd_config.bak\"\n\nelse\n    >&2 echo 'Remediation is not applicable, nothing was done'\nfi"
  ),
  "references": {
    "NIST": ["CM-6(a)", "AC-17(a)", "AC-2(5)", "AC-12", "AC-17(a)", "SC-10", "CM-6(a)"]
  }
},

{
  "id": "xccdf_org.ssgproject.content_rule_sshd_set_idle_timeout",
  "title": "Set SSH Client Alive Interval",
  "severity": "medium",
  "description": (
    "SSH allows administrators to set a network responsiveness timeout interval. After this interval has passed, the unresponsive client will be automatically logged out.\n\nTo set this timeout interval, edit the following line in /etc/ssh/sshd_config as follows:\nClientAliveInterval 600\n\n\nThe timeout interval is given in seconds. For example, have a timeout of 10 minutes, set interval to 600.\n\nIf a shorter timeout has already been set for the login shell, that value will preempt any SSH setting made in /etc/ssh/sshd_config. Keep in mind that some processes may stop SSH from correctly detecting that the user is idle."
  ),
  "rationale": (
    "Terminating an idle ssh session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been let unattended."
  ),
  "fix": (
    "# Remediation is applicable only in certain platforms\nif rpm --quiet -q kernel; then\n\nsshd_idle_timeout_value='600'\n\n\n\nif [ -e \"/etc/ssh/sshd_config\" ] ; then\n    \n    LC_ALL=C sed -i \"/^\\s*ClientAliveInterval\\s\\+/Id\" \"/etc/ssh/sshd_config\"\nelse\n    touch \"/etc/ssh/sshd_config\"\nfi\n# make sure file has newline at the end\nsed -i -e '$a\\' \"/etc/ssh/sshd_config\"\n\ncp \"/etc/ssh/sshd_config\" \"/etc/ssh/sshd_config.bak\"\n# Insert at the beginning of the file\nprintf '%s\\n' \"ClientAliveInterval $sshd_idle_timeout_value\" > \"/etc/ssh/sshd_config\"\ncat \"/etc/ssh/sshd_config.bak\" >> \"/etc/ssh/sshd_config\"\n# Clean up after ourselves.\nrm \"/etc/ssh/sshd_config.bak\"\n\nelse\n    >&2 echo 'Remediation is not applicable, nothing was done'\nfi"
  ),
  "references": {
    "NIST": ["CM-6(a)", "AC-17(a)", "AC-2(5)", "AC-12", "AC-17(a)", "SC-10", "CM-6(a)"]
  }
},

{
  "id": "xccdf_org.ssgproject.content_rule_mount_option_boot_nosuid",
  "title": "Add nosuid Option to /boot",
  "severity": "medium",
  "description": (
    "The nosuid mount option can be used to prevent execution of setuid programs in /boot. The SUID and SGID permissions should not be required on the boot partition. Add the nosuid option to the fourth column of /etc/fstab for the line which controls mounting of /boot."
  ),
  "rationale": (
    "The presence of SUID and SGID executables should be tightly controlled. Users should not be able to execute SUID or SGID binaries from boot partitions."
  ),
  "fix": (
    "# Remediation is applicable only in certain platforms\nif ( ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ) && ! ( [ -f /.dockerenv ] || [ -f /run/.containerenv ] ) ); then\n\nfunction perform_remediation {\n    \n        # the mount point /boot has to be defined in /etc/fstab\n        # before this remediation can be executed. In case it is not defined, the\n        # remediation aborts and no changes regarding the mount point are done.\n        mount_point_match_regexp=\"$(printf \"^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]\" \"/boot\")\"\n\n    grep \"$mount_point_match_regexp\" -q /etc/fstab \\\n        || { echo \"The mount point '/boot' is not even in /etc/fstab, so we can't set up mount options\" >&2;\n                echo \"Not remediating, because there is no record of /boot in /etc/fstab\" >&2; return 1; }\n    \n\n\n    mount_point_match_regexp=\"$(printf \"^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]\" /boot)\"\n\n    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab\n    if ! grep -q \"$mount_point_match_regexp\" /etc/fstab; then\n        # runtime opts without some automatic kernel/userspace-added defaults\n        previous_mount_opts=$(grep \"$mount_point_match_regexp\" /etc/mtab | head -1 |  awk '{print $4}' \\\n                    | sed -E \"s/(rw|defaults|seclabel|nosuid)(,|$)//g;s/,$//\")\n        [ \"$previous_mount_opts\" ] && previous_mount_opts+=\",\" \n        # In iso9660 filesystems mtab could describe a \"blocksize\" value, this should be reflected in\n        # fstab as \"block\".  The next variable is to satisfy shellcheck SC2050.\n        fs_type=\"\"\n        if [  \"$fs_type\" == \"iso9660\" ] ; then\n            previous_mount_opts=$(sed 's/blocksize=/block=/' <<< \"$previous_mount_opts\")\n        fi\n        echo \" /boot  defaults,${previous_mount_opts}nosuid 0 0\" >> /etc/fstab\n    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it\n    elif ! grep \"$mount_point_match_regexp\" /etc/fstab | grep -q \"nosuid\"; then\n        previous_mount_opts=$(grep \"$mount_point_match_regexp\" /etc/fstab | awk '{print $4}')\n        sed -i \"s|\\(${mount_point_match_regexp}.*${previous_mount_opts}\\)|\\1,nosuid|\" /etc/fstab\n    fi\n\n\n    if mkdir -p \"/boot\"; then\n        if mountpoint -q \"/boot\"; then\n            mount -o remount --target \"/boot\"\n        fi\n    fi\n}\n\nperform_remediation\n\nelse\n    >&2 echo 'Remediation is not applicable, nothing was done'\nfi"
  ),
  "references": {
    "NIST": ["CM-7(a)", "CM-7(b)", "CM-6(a)", "AC-6", "AC-6(1)", "MP-7"]
  }
},

{
  "id": "xccdf_org.ssgproject.content_rule_mount_option_dev_shm_nodev",
  "title": "Add nodev Option to /dev/shm",
  "severity": "medium",
  "description": (
    "The nodev mount option can be used to prevent creation of device files in /dev/shm. Legitimate character and block devices should not exist within temporary directories like /dev/shm. Add the nodev option to the fourth column of /etc/fstab for the line which controls mounting of /dev/shm."
  ),
  "rationale": (
    "The only legitimate location for device files is the /dev directory located on the root partition. The only exception to this is chroot jails."
  ),
  "fix": (
    "# Remediation is applicable only in certain platforms\nif ( ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ) && ! ( [ -f /.dockerenv ] || [ -f /run/.containerenv ] ) ); then\n\nfunction perform_remediation {\n    \n\n\n    mount_point_match_regexp=\"$(printf \"^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]\" /dev/shm)\"\n\n    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab\n    if ! grep -q \"$mount_point_match_regexp\" /etc/fstab; then\n        # runtime opts without some automatic kernel/userspace-added defaults\n        previous_mount_opts=$(grep \"$mount_point_match_regexp\" /etc/mtab | head -1 |  awk '{print $4}' \\\n                    | sed -E \"s/(rw|defaults|seclabel|nodev)(,|$)//g;s/,$//\")\n        [ \"$previous_mount_opts\" ] && previous_mount_opts+=\",\" \n        # In iso9660 filesystems mtab could describe a \"blocksize\" value, this should be reflected in\n        # fstab as \"block\".  The next variable is to satisfy shellcheck SC2050.\n        fs_type=\"tmpfs\"\n        if [  \"$fs_type\" == \"iso9660\" ] ; then\n            previous_mount_opts=$(sed 's/blocksize=/block=/' <<< \"$previous_mount_opts\")\n        fi\n        echo \"tmpfs /dev/shm tmpfs defaults,${previous_mount_opts}nodev 0 0\" >> /etc/fstab\n    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it\n    elif ! grep \"$mount_point_match_regexp\" /etc/fstab | grep -q \"nodev\"; then\n        previous_mount_opts=$(grep \"$mount_point_match_regexp\" /etc/fstab | awk '{print $4}')\n        sed -i \"s|\\(${mount_point_match_regexp}.*${previous_mount_opts}\\)|\\1,nodev|\" /etc/fstab\n    fi\n\n\n    if mkdir -p \"/dev/shm\"; then\n        if mountpoint -q \"/dev/shm\"; then\n            mount -o remount --target \"/dev/shm\"\n        fi\n    fi\n}\n\nperform_remediation\n\nelse\n    >&2 echo 'Remediation is not applicable, nothing was done'\nfi"
  ),
  "references": {
    "NIST": ["CM-7(a)", "CM-7(b)", "CM-6(a)", "AC-6", "AC-6(1)", "MP-7"]
  }
}

]

def populate():
    conn = psycopg2.connect(
        dbname="stigdb",
        user="stig_user",
        password="your_secure_password",
        host="localhost",
        port="5432"
    )
    cur = conn.cursor()

    # JSONB table schema
    cur.execute("""
        CREATE TABLE IF NOT EXISTS stig_rules (
            id TEXT PRIMARY KEY,
            title TEXT,
            severity TEXT,
            description TEXT,
            rationale TEXT,
            fix TEXT,
            rule_references JSONB
        );
    """)

    for rule in STIG_RULES:
        cur.execute("""
            INSERT INTO stig_rules (
                id, title, severity, description, rationale, fix, rule_references
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO NOTHING;
        """, (
            rule["id"],
            rule["title"],
            rule["severity"],
            rule["description"],
            rule["rationale"],
            rule["fix"],
            json.dumps(rule["references"])
        ))

    conn.commit()
    cur.close()
    conn.close()
    print("✅ STIG rules populated into PostgreSQL.")

if __name__ == "__main__":
    populate()
