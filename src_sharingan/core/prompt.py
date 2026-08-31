from prompt_toolkit import prompt
# from core.

def main():
    while True:
        try:
            text = prompt("Sharingan> ")
            print(f"You said: {text}")
            if text.split()[0] == 'enumerate' or 'scan':
               pass 
            if text.lower() in ['exit', 'quit']:
                break
        except KeyboardInterrupt:
            continue
        except EOFError:
            break

if __name__ == '__main__':
    main()