from daemonaudit import __version__

DEMON = r"""
   ,     ,
  (\____/)     daemonaudit v{v}
   (_oo_)      who can hurt your agent — and how badly
     (O)
   __||__    \)
 []/______\[] /
 / \______/ \/
/    /__\
(\   /____\
"""


def banner() -> str:
    return DEMON.format(v=__version__)
