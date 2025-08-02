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
