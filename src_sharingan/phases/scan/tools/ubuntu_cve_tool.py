import re
import shutil
import subprocess

import requests


class UbuntuCveTool:
    """Cruza uma CVE encontrada pelo `vulners` (casando por CPE — produto+versão
    upstream) com o rastreador de CVE oficial da Ubuntu (ubuntu.com/security/cves)
    para saber se o pacote .deb *de fato instalado* já corrige aquela CVE.

    Existe porque um match por CPE não sabe de uma coisa muito comum: Debian e
    Ubuntu corrigem CVE via backport de segurança SEM subir a versão upstream que
    o `nmap -sV` reporta — só o sufixo de revisão muda (ex.: `9.6p1-3ubuntu13.3`
    -> `9.6p1-3ubuntu13.18`). Isso gera falso positivo com muita frequência: o
    vulners aponta `OpenSSH 9.6p1` como vulnerável a uma CVE mesmo quando o pacote
    instalado já tem o patch aplicado há várias revisões.

    Usa `dpkg --compare-versions` para comparar a versão instalada com a versão
    corrigida publicada pela Ubuntu, em vez de reimplementar um parser de versão
    do Debian (que tem regras próprias — epoch, tilde, etc. — e é fácil de errar).
    Segue o mesmo princípio do resto do projeto: orquestrar uma ferramenta madura
    já existente em vez de escrever a nossa.
    """

    base_url = 'https://ubuntu.com/security/cves'
    _BRANCH_RE = re.compile(r'(\d+ubuntu\d+)')
    _UPSTREAM_UBUNTU_RE = re.compile(r'\bUbuntu\b\s*-?\s*$')

    @classmethod
    def is_available(cls) -> bool:
        return shutil.which('dpkg') is not None

    @classmethod
    def check(cls, cve: str, product: str, installed_version: str) -> dict:
        """Retorna `{'status': ..., 'detail': ...}`.

        `status` é um de: `'patched'` (Ubuntu já corrigiu e a versão instalada já
        tem o patch), `'vulnerable'` (Ubuntu já tem correção, mas a versão
        instalada é anterior a ela — confirmado), `'not_affected'` (a própria
        Ubuntu marcou o pacote como não afetado por essa CVE) ou `'unknown'`
        (rodou mas não deu pra concluir — alvo não é Ubuntu, pacote não rastreado
        para essa CVE, ou falha de rede/parsing — nunca derruba o scan).
        """
        branch = cls._extract_branch(installed_version or '')
        if not branch:
            return {
                'status': 'unknown',
                'detail': (
                    'Verificação automática só cobre pacotes com revisão Ubuntu '
                    '(ex.: 3ubuntu13.18) por enquanto.'
                ),
            }

        try:
            response = requests.get(f'{cls.base_url}/{cve}.json', timeout=10)
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            return {'status': 'unknown', 'detail': f'Não foi possível consultar o rastreador da Ubuntu: {e}'}

        package_name = (product or '').strip().lower()
        pkg_entry = next(
            (p for p in data.get('packages', []) if (p.get('name') or '').lower() == package_name),
            None,
        )
        if not pkg_entry:
            return {
                'status': 'unknown',
                'detail': f"Pacote '{package_name}' não encontrado no rastreador da Ubuntu para essa CVE.",
            }

        statuses = pkg_entry.get('statuses', [])

        # 1) Prioridade: um status 'released' cuja versão corrigida contém a mesma
        #    branch (`3ubuntu13`) da versão instalada — é o caso mais preciso,
        #    porque a branch já amarra a comparação à família certa de revisão.
        released = next(
            (s for s in statuses if s.get('status') == 'released' and branch in (s.get('description') or '')),
            None,
        )
        if released:
            codename = released.get('release_codename', '?')
            fixed_version = released.get('description')
            debian_version = cls._to_debian_version(installed_version)
            if fixed_version and debian_version and cls._installed_is_at_least(debian_version, fixed_version):
                return {
                    'status': 'patched',
                    'detail': f"Corrigido pela Ubuntu em {fixed_version} ({codename}).",
                }
            return {
                'status': 'vulnerable',
                'detail': (
                    f"Correção só a partir de {fixed_version} ({codename}) — "
                    'versão instalada é anterior.'
                ),
            }

        # 2) Sem status 'released' correlacionável pela branch, procura um status
        #    'not-affected'/'ignored' — esses normalmente não trazem número de
        #    versão no texto (é uma explicação, não uma versão), então não dá pra
        #    correlacionar por branch; tratamos como válido de forma geral.
        not_affected = next(
            (s for s in statuses if s.get('status') in ('not-affected', 'ignored')),
            None,
        )
        if not_affected:
            codename = not_affected.get('release_codename', '?')
            return {'status': 'not_affected', 'detail': f"Ubuntu marcou como não afetado ({codename})."}

        return {
            'status': 'unknown',
            'detail': 'Rastreador da Ubuntu não tem status de correção compatível com a revisão instalada.',
        }

    @classmethod
    def _extract_branch(cls, version: str) -> str | None:
        match = cls._BRANCH_RE.search(version)
        return match.group(1) if match else None

    @classmethod
    def _to_debian_version(cls, nmap_version: str) -> str | None:
        """Reconstrói uma versão no formato Debian (`9.6p1-3ubuntu13.18`) a partir
        do jeito que o nmap reporta (`9.6p1 Ubuntu-3ubuntu13.18` ou
        `9.6p1 Ubuntu 3ubuntu13.18`) — `dpkg --compare-versions` espera o formato
        Debian, não o texto solto do banner."""
        if not nmap_version:
            return None
        match = cls._BRANCH_RE.search(nmap_version)
        if not match:
            return None
        branch_and_suffix = nmap_version[match.start():].strip()
        upstream = cls._UPSTREAM_UBUNTU_RE.sub('', nmap_version[:match.start()]).strip()
        if not upstream:
            return None
        return f'{upstream}-{branch_and_suffix}'

    @staticmethod
    def _installed_is_at_least(installed: str, fixed: str) -> bool:
        # Remove epoch (`N:`) dos dois lados — o nmap não reporta epoch no banner,
        # então comparar direto com o epoch presente só na versão da Ubuntu faria
        # todo pacote instalado parecer "mais antigo" que a correção, mesmo já
        # atualizado.
        installed_no_epoch = re.sub(r'^\d+:', '', installed.strip())
        fixed_no_epoch = re.sub(r'^\d+:', '', fixed.strip())
        result = subprocess.run(
            ['dpkg', '--compare-versions', installed_no_epoch, 'ge', fixed_no_epoch],
            capture_output=True,
        )
        return result.returncode == 0
