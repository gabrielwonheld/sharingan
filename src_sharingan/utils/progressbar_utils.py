import math


class Progress_bar:
    @staticmethod
    def progress_callback(current, total):
        percent_complete = (current / total) * 100
        num_hash = math.floor(percent_complete)
        barra = '#' * num_hash
        # print(f"Progress: {percent_complete:.2f}% ({current} of {total} bytes)", end="\r")
        print(
            f'\rProgress: {percent_complete:.2f}% [{barra:<100}] ({current} of {total} bytes)',
            end='',
        )
