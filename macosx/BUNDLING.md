# Table of Contents
---
   
 * [Jhbuild](#jhbuild)
 	* Possible error
 * [gtk-mac-bundler](#bundler)
 * [How to use](#howto)
 	* Prerequisite
 	* Usage

## <a name="jhbuild"></a>Jhbuild

In order to set up Jhbuild properly before building Nmap suite, follow the tutorial at [https://wiki.gnome.org/Projects/GTK%2B/OSX/Building](https://wiki.gnome.org/Projects/GTK%2B/OSX/Building), but keep reading this file if you encounter any error...

If you had any error, just type the following command to delete jhbuild,

	$ rm -rf ~/.local ~/.new_local ~/.cache ~/.config ~/Source/jhbuild ~/Source/pyenv ~/Library/Caches/pip* ~/gtk

And we'll start over together:

1.	First, simply download the following script in your _$HOME_ directory ([https://git.gnome.org/browse/gtk-osx/plain/gtk-osx-build-setup.sh](https://git.gnome.org/browse/gtk-osx/plain/gtk-osx-build-setup.sh)). Edit it to make sure that `MACOSX_DEPLOYMENT_TARGET` exists and is set to the lowest supported version of OS X, e.g. "10.11". Then run it:

	~~~~
	$ sh gtk-osx-build-setup.sh
	~~~~
	
	And add it to your _$PATH_, so you can run jhbuild without the absolute path:
	
	~~~~
	$ export PATH=$HOME/.local/bin:$PATH
	~~~~
	
2.	In `~/.jhbuildrc-custom`, make sure that this line is setup properly and matches `MACOSX_DEPLOYMENT_TARGET` from step 1:

	~~~~
	setup_sdk(target="10.11")
	~~~~
	
3.	Now do,

	~~~~
	$ jhbuild bootstrap-gtk-osx
	~~~~
	
	To install missing dependencies (with **--force** option to force rebuilding).<br/>
	
4.	And,

	~~~~
	$ jhbuild build meta-gtk-osx-bootstrap
	$ jhbuild build meta-gtk-osx-core

5. Now we need Python2 and the GTK2 bindings for it, but gtk-osx has built
Python3, and the bindings will prefer that even though the dev headers aren't
present. Specifically, we need pycairo prior to 1.19 (when they dropped Python2
support) and gtk-integration-python. There's got to be a better way, but what I
did was first install python2:

	$ jhbuild build python

Then install pycairo. This is necessary because if it's missing for Python 2,
the other bindings won't build for Python 2 either. Make sure version is less
than 1.19 in ~/.cache/jhbuild/gtk-osx-python.modules. This may "succeed" but it
will have built the Python3 bindings. Clear out the build tree and make sure
the source will prefer python2:

	$ jhbuild build pycairo
	$ rm -rf ~/.cache/jhbuild/build/pycairo-*
	$ sed -i 's/python3/python2/' ~/gtk/source/pycairo-*/meson_options.txt
	$ jhbuild build pycairo

Now build the rest of the python bindings. Some of these will fail (and maybe
they failed as prereqs for pycairo earlier), so hang on and I'll tell you how
to fix those:

	$ jhbuild build meta-gtk-osx-python

Ok, when you get a failure, that's your chance to reconfigure with python2.
Jhbuild will give you some options; choose "4. start a shell" and then check
for the proper configuration command (may be visible in scrollback, otherwise
check config.log) and copy it. Clear out the build directory (probably the
current directory, ~/.cache/jhbuild/build/package-name-version/*) then from
there run the configuration command with PYTHON variable overridden, e.g.:

	$ PYTHON=$(which python2) ~/gtk/source/package-name-version/configure --some-options

Now exit that shell and go to the build step. This might mean "ignore error and
continue with build" or it might mean "rerun step build" depending on when the
error happened.

### Possible error

For those of you who have this error while trying to make,

~~~~
svn: E155021: This client is too old to work with the working copy at...
~~~~

You need to **update SVN**.<br/>
Go to [http://www.wandisco.com/subversion/download#osx](http://www.wandisco.com/subversion/download#osx) and download and install the approriate version for your OS.

Now, add the path for the new SVN version to your _$PATH_:

~~~~
$ export PATH=/opt/subversion/bin:$PATH
~~~~

## <a name="bundler"></a>gtk-mac-bundler

Now that Jhbuild is properly configured, we need to install **gtk-mac-bundler** in order to render the bundle file:

~~~~
$ git clone git://git.gnome.org/gtk-mac-bundler
$ cd gtk-mac-bundler
$ make install
~~~~

## <a name="howto"></a>How to use
#### Prerequisite:
—`openssl.modules`:

This is a jhbuild moduleset that can be used to build/update openssl.

#### Usage:

Now use it like this:
    
~~~~
$ jhbuild -m openssl.modules build nmap-deps
~~~~
