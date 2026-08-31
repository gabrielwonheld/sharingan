
class SetEnvService:
    
    def set_env(self, key=None, value=None):
        
        self.env = {
            'host': '',
            'ports': list[int],
            'name': ''
        }          

        if len(key) < 3:
            print("[red]Usage: set <target> <ip>[/red]")
        
        for x in self.env.keys():
            if key == x:
                self.env[x] = value
                # self.console.print(f"[green]{x} set to {value}[/green]")
                print(self.env)
                return self.env
        # self.console.print("[red]Invalid target[/red]")        