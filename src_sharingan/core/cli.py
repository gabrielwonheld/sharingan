import argparse


class Cli:
    @staticmethod
    def parse_args():

        parser = argparse.ArgumentParser(description='Monitoramento de hosts')
        parser.add_argument(
            '--monitor', '-m', action='store_true', help='service monitoring'
        )
        parser.add_argument(
            '--active', '-a', action='store_true', help='get active hosts'
        )
        parser.add_argument(
            '--inactive', '-i', action='store_true', help='get inactive hosts'
        )
        parser.add_argument(
            '--inventory', '-f', type=str, help='Path to hosts file (YAML)'
        )
        parser.add_argument(
            '--spider', '-p', action='store_true', help='crawl in sites'
        )
        parser.add_argument('--url', '-u', type=str, help='Website URL')
        parser.add_argument('--domain', '-d', type=str, help='Website domain')
        parser.add_argument('--output', '-o', type=str, help='Path to file')
        parser.add_argument('--tasks', '-t', type=int, default=5, help='tasks')
        parser.add_argument('--depth', '-x', type=int, default=3, help='tasks')

        return parser.parse_args()
