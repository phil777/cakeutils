
import logging

def get_console_logger(name):
    log = logging.getLogger(name)
    log.setLevel(1)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    log.addHandler(console_handler)
    return log

