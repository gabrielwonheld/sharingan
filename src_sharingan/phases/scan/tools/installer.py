import shutil
import subprocess


class ToolInstaller:
    """Installs the external tools used by the Scan phase.

    Important: there's no universal "apt install rustscan". `nmap` and the
    `exploitdb` package (which brings `searchsploit`) have a reliable package
    via apt/dnf/pacman/brew — `exploitdb` is the official package name on
    Kali (kali.org/tools/exploitdb). RustScan, on the other hand, is **not
    packaged** in the apt/dnf/pacman of any mainstream distro (not even
    Kali); the official install methods are `cargo install rustscan`,
    Homebrew on macOS, or manually downloading the `.deb` from the GitHub
    releases page. That's why `install_rustscan` only tries cargo/brew — it
    doesn't pretend an apt/dnf/pacman package exists when, in practice, it
    doesn't.

    Confirming with the user ("want to install it?") is the console layer's
    responsibility — this class only runs the install once that's already
    decided.
    """

    @staticmethod
    def _run(command: list[str]) -> bool:
        # Deliberately doesn't capture stdout/stderr: it inherits the current
        # terminal so a possible sudo password prompt shows up normally.
        try:
            result = subprocess.run(command)
            return result.returncode == 0
        except FileNotFoundError:
            return False

    @classmethod
    def install_nmap(cls) -> bool:
        if shutil.which('apt-get'):
            return cls._run(['sudo', 'apt-get', 'install', '-y', 'nmap'])
        if shutil.which('dnf'):
            return cls._run(['sudo', 'dnf', 'install', '-y', 'nmap'])
        if shutil.which('pacman'):
            return cls._run(['sudo', 'pacman', '-S', '--noconfirm', 'nmap'])
        if shutil.which('brew'):
            return cls._run(['brew', 'install', 'nmap'])
        return False

    @classmethod
    def install_searchsploit(cls) -> bool:
        # Also installs the package that provides `xmllint` — `searchsploit --nmap`
        # depends on it to parse the nmap XML (without it, it exits with "Please install
        # xmllint" and status 1; see `SearchsploitTool.xmllint_binary`). `exploitdb`
        # alone doesn't guarantee that on every distro.
        if shutil.which('apt-get'):
            return cls._run(['sudo', 'apt-get', 'install', '-y', 'exploitdb', 'libxml2-utils'])
        if shutil.which('dnf'):
            return cls._run(['sudo', 'dnf', 'install', '-y', 'exploitdb', 'libxml2'])
        if shutil.which('pacman'):
            return cls._run(['sudo', 'pacman', '-S', '--noconfirm', 'exploitdb', 'libxml2'])
        if shutil.which('brew'):
            return cls._run(['brew', 'install', 'exploitdb', 'libxml2'])
        return False

    @classmethod
    def install_rustscan(cls) -> bool:
        if shutil.which('cargo'):
            return cls._run(['cargo', 'install', 'rustscan'])
        if shutil.which('brew'):
            return cls._run(['brew', 'install', 'rustscan'])
        return False

    @classmethod
    def install_subfinder(cls) -> bool:
        # Packaged on Kali's apt (kali.org/tools/subfinder) and on Homebrew;
        # `go install` is ProjectDiscovery's own documented method everywhere
        # else — same risk tier as rustscan's `cargo install` (builds from
        # source via the module proxy, not an opaque downloaded binary).
        if shutil.which('apt-get'):
            return cls._run(['sudo', 'apt-get', 'install', '-y', 'subfinder'])
        if shutil.which('brew'):
            return cls._run(['brew', 'install', 'subfinder'])
        if shutil.which('go'):
            return cls._run(['go', 'install', 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'])
        return False

    @classmethod
    def install_gobuster(cls) -> bool:
        # Packaged on Kali's apt (kali.org/tools/gobuster) and on Homebrew;
        # `go install` is gobuster's own documented method everywhere else —
        # same risk tier as rustscan's `cargo install`/subfinder's `go install`.
        if shutil.which('apt-get'):
            return cls._run(['sudo', 'apt-get', 'install', '-y', 'gobuster'])
        if shutil.which('brew'):
            return cls._run(['brew', 'install', 'gobuster'])
        if shutil.which('go'):
            return cls._run(['go', 'install', 'github.com/OJ/gobuster/v3@latest'])
        return False

    @classmethod
    def install(cls, tool_name: str) -> bool:
        installers = {
            'nmap': cls.install_nmap,
            'searchsploit': cls.install_searchsploit,
            'rustscan': cls.install_rustscan,
            'subfinder': cls.install_subfinder,
            'gobuster': cls.install_gobuster,
        }
        installer = installers.get(tool_name)
        if installer is None:
            return False
        return installer()

    @staticmethod
    def manual_install_hint(tool_name: str) -> str:
        hints = {
            'nmap': 'https://nmap.org/download.html',
            'searchsploit': (
                'apt install exploitdb works on Kali; on other distros, '
                'see https://gitlab.com/exploit-database/exploitdb (clone it and add it to PATH). '
                'Either way, --nmap mode also needs xmllint: '
                'apt install libxml2-utils (Fedora/Arch/macOS: libxml2 package)'
            ),
            'rustscan': (
                'no official apt/dnf/pacman package — use "cargo install rustscan" or download the .deb from '
                'https://github.com/RustScan/RustScan/releases and run "sudo dpkg -i <file>.deb"'
            ),
            'vulners': (
                'not a package, it is an nmap NSE script — clone https://github.com/vulnersCom/nmap-vulners, '
                'copy vulners.nse into nmap\'s script folder and run "nmap --script-updatedb"'
            ),
            'subfinder': (
                'apt install subfinder works on Kali; elsewhere use "brew install subfinder" or '
                '"go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" '
                '(see https://github.com/projectdiscovery/subfinder)'
            ),
            'gobuster': (
                'apt install gobuster works on Kali; elsewhere use "brew install gobuster" or '
                '"go install github.com/OJ/gobuster/v3@latest" (see https://github.com/OJ/gobuster)'
            ),
        }
        return hints.get(tool_name, '')
