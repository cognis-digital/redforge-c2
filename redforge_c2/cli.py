from cognis_mil import make_cli
from .core import scan
from . import __version__
def main(): make_cli("redforge-c2", scan, version=__version__)
if __name__ == "__main__": main()
