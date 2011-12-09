import os,subprocess


class Term(object):
    def __init__(self, cmd, title="", keepterm=True):
        self.cmd = cmd
        self.title = title
        self.hold = True
        self.keepterm = keepterm
    def cmdline(self):
        return []
    def run(self):
        c = self.cmdline()
        self.p = subprocess.Popen(c)
    def wait(self):
        return self.p.wait()
    def kill(self):
        self.p.kill()

class XTerm(Term):
    def cmdline(self):
        c = ["xterm", "-title", self.title]
        if self.keepterm:
            c.append("-hold")
        c += ["-e", self.cmd]
        return c

class SideLog(object):
    def __init__(self, term=XTerm, keepterm=True, title=""):
        self.term = term
        self.keepterm = keepterm
        self.title=title
        self.open_term()
        
    def open_term(self):
        self.r, self.w = os.pipe()
        self.running_term = self.term("cat 0<&%i" % self.r, keepterm=self.keepterm, title=self.title)
        self.running_term.run()
    def log(self, msg):
        os.write(self.w, msg)

    def stop(self):
        os.close(self.w)
        self.running_term.kill()
        self.running_term.wait()
    
