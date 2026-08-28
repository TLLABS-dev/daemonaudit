from daemonaudit import __version__

DEMON = r"""
   ^      ^
   |\    /|
  (  o  o  )    daemonaudit v{v}
   \  ~~  /     who can hurt your agent — and how badly
    `----´
"""


def banner() -> str:
    return DEMON.format(v=__version__)
