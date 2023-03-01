from os.path import join, dirname, abspath, normpath
import sys, os
import platform


bundlepath = sys.argv[0]

bundle_contents = join(bundlepath, 'Contents')
bundle_res = join(bundle_contents, 'Resources')

bundle_lib = join(bundle_res, 'lib')
bundle_bin = join(bundle_res, 'bin')
bundle_data = join(bundle_res, 'share')
bundle_etc = join(bundle_res, 'etc')

os.environ['XDG_DATA_DIRS'] = bundle_data
os.environ['DYLD_LIBRARY_PATH'] = bundle_lib
os.environ['LD_LIBRARY_PATH'] = bundle_lib
os.environ['GTK_DATA_PREFIX'] = bundle_res
os.environ['GTK_EXE_PREFIX'] = bundle_res
os.environ['GTK_PATH'] = bundle_res

os.environ['PANGO_RC_FILE'] = join(bundle_etc, 'pango', 'pangorc')
os.environ['PANGO_SYSCONFDIR'] = bundle_etc
os.environ['PANGO_LIBDIR'] = bundle_lib
os.environ['GDK_PIXBUF_MODULE_FILE'] = join(bundle_lib, 'gdk-pixbuf-2.0',
                                                '2.10.0', 'loaders.cache')
if int(platform.release().split('.')[0]) > 10:
    os.environ['GTK_IM_MODULE_FILE'] = join(bundle_etc, 'gtk-3.0',
                                            'gtk.immodules')

os.environ['GI_TYPELIB_PATH'] = join(bundle_lib, 'girepository-1.0')

#Set $PYTHON to point inside the bundle
PYVER = 'python3.10'
sys.path.append(bundle_res)

os.environ['USERPROFILE'] = os.environ['HOME']
os.environ['APPDATA'] = join(os.environ['HOME'], 'Library', 'Application Support')
# Replace my_app with the file or module with your main() function.
from zenmapGUI import App
App.run()

