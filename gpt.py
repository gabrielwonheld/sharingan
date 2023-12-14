'''def format_header(text, width):
    return f'{width * "_"}\n{text.center(width)}\n{width * "_"}'

hosts = ['192.168.26.133', '40.37.0.5', '35.55.78.10', '192.168.0.101', '192.168.0.126']

inactive_hosts = [
    '192.168.26.133',
    '40.37.0.5',
    '35.55.78.10',
    '192.168.0.101',
    '192.168.0.126',
    '192.168.26.133',
    '40.37.0.5',
    '35.55.78.10',
    '192.168.0.101',
    '192.168.0.126'
]

total_hosts = len(hosts)
total_inactive = len(inactive_hosts)

max_item_length = max(len(max(hosts, key=len)), len('Host Inativos'))
width = max_item_length + 6  # Adicione alguma margem

header = format_header("HOSTS INATIVOS", width)
info = f"Host Inativos: {', '.join(inactive_hosts)}"
total_info = f"Total de hosts: {total_hosts}\nTotal de hosts Inativos: {total_inactive}"
header = format_header("HOSTS INATIVOS", width)

print(header)
print(info)
print(total_info)
print(header)'''

host=['192.168.0.1', '192.168.0.101', '192.168.0.126','40.37.0.5','35.55.78.10','192.168.26.133']

valor = ''.join(host)
print(len(valor))
