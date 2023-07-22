import os
import platform
import sys
import logging
import argparse
from pathlib import Path
from typing import Dict
from zenmapGUI import App

class ReadableDir(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        prospective_dir = values
        if not os.path.isdir(prospective_dir):
            raise argparse.ArgumentError(self, f"{prospective_dir} is not a valid path")
        if os.access(prospective_dir, os.R_OK):
            setattr(namespace, self.dest, prospective_dir)
        else:
            raise argparse.ArgumentError(self, f"{prospective_dir} is not a readable dir")

class ZenmapLauncher:
    ENVIRONMENT_PATH_KEYS = {
        'XDG_DATA_DIRS': 'share',
        'DYLD_LIBRARY_PATH': 'lib',
        'LD_LIBRARY_PATH': 'lib',
        'GTK_DATA_PREFIX': None,
        'GTK_EXE_PREFIX': None,
        'GTK_PATH': None,
        'PANGO_RC_FILE': 'etc/pango/pangorc',
        'PANGO_SYSCONFDIR': 'etc',
        'PANGO_LIBDIR': 'lib',
        'GDK_PIXBUF_MODULE_FILE': 'lib/gdk-pixbuf-2.0/2.10.0/loaders.cache',
        'GI_TYPELIB_PATH': 'lib/girepository-1.0'
    }

    def __init__(self, bundle_path: str):
        self.bundle_path = Path(bundle_path)
        self.contents_path = self.bundle_path / 'Contents' / 'Resources'
        self.logger = self.get_logger()

    @staticmethod
    def get_logger():
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        return logging.getLogger(__name__)

    def get_environment_paths(self) -> Dict[str, Path]:
        env_paths = {}
        for key, sub_path in self.ENVIRONMENT_PATH_KEYS.items():
            env_paths[key] = self.contents_path / sub_path if sub_path else self.contents_path

        env_paths['USERPROFILE'] = Path.home()
        env_paths['APPDATA'] = Path.home() / 'Library' / 'Application Support'

        return env_paths

    def set_environment_variables(self, path_dict: Dict[str, Path]) -> None:
        for key, path in path_dict.items():
            if path.exists():
                os.environ[key] = str(path)
            else:
                self.logger.error(f"Path does not exist: {path}")
                raise FileNotFoundError(f"Path does not exist: {path}")

    def run(self):
        try:
            env_paths = self.get_environment_paths()
            self.set_environment_variables(env_paths)

            # Append the path for Python modules
            sys.path.append(str(self.contents_path))

            self.logger.info(f"Running on platform: {platform.platform()} with Python version: {platform.python_version()}")
            App.run()

        except (FileNotFoundError, argparse.ArgumentError) as e:
            self.logger.error(f"Error: {e}")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"Unhandled Launcher Error: {e}", exc_info=True)
            sys.exit(1)

def get_command_line_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Zenmap launcher script")
    parser.add_argument("bundlepath", action=ReadableDir, help="path to the application bundle")
    return parser.parse_args()

def main():
    args = get_command_line_arguments()
    launcher = ZenmapLauncher(args.bundlepath)
    launcher.run()

if __name__ == '__main__':
    main()
