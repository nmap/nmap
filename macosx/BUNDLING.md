# Table of Contents
---
   
 * [Jhbuild](#jhbuild)
 	* Possible error
 * [gtk-mac-bundler](#bundler)
 * [How to use](#howto)
 	* Prerequisite
 	* Usage

## <a name="jhbuild"></a>Jhbuild

In order to set up Jhbuild properly before building Nmap suite, follow the tutorial at https://gitlab.gnome.org/GNOME/gtk-osx/-/wikis/home , but keep reading this file if you encounter any error...

If you had any error, just type the following command to delete jhbuild,

	$ rm -rf ~/.local ~/.new_local ~/.cache ~/.config ~/Source/jhbuild ~/Source/pyenv ~/Library/Caches/pip* ~/gtk

And we'll start over together:

1.	First, simply download the following script in your _$HOME_ directory https://gitlab.gnome.org/GNOME/gtk-osx/raw/master/gtk-osx-setup.sh

	~~~~
	$ sh gtk-osx-setup.sh
	~~~~
	
	And add it to your _$PATH_, so you can run jhbuild without the absolute path:
	
	~~~~
	$ export PATH=$HOME/.local/bin:$PATH
	~~~~
	
2.	In `~/.config/jhbuildrc-custom`, make sure that this line is setup properly:

	~~~~
	setup_sdk(target="10.14")
	~~~~
	
3.	Now do:

	~~~~
	$ jhbuild bootstrap-gtk-osx
	~~~~
	
	To install missing dependencies (with **--force** option to force rebuilding).<br/>
	
4.	And,

	~~~~
	$ jhbuild build meta-gtk-osx-bootstrap
	$ jhbuild build meta-gtk-osx-gtk3
	$ jhbuild build meta-gtk-osx-python3-gtk3


### Possible error

For those of you who have this error while trying to make,

~~~~
svn: E155021: This client is too old to work with the working copy at...
~~~~

You need to **update SVN**.<br/>
Go to [http://www.wandisco.com/subversion/download#osx](http://www.wandisco.com/subversion/download#osx) and download and install the appropriate version for your OS.

Now, add the path for the new SVN version to your _$PATH_:

~~~~
$ export PATH=/opt/subversion/bin:$PATH
~~~~

## <a name="bundler"></a>gtk-mac-bundler

Now that Jhbuild is properly configured, we need to install **gtk-mac-bundler** in order to render the bundle file:

~~~~
$ git clone https://gitlab.gnome.org/GNOME/gtk-mac-bundler.git
$ cd gtk-mac-bundler
$ make install
~~~~

## <a name="howto"></a>How to use
#### Prerequisite:
`openssl.modules`:

This is a jhbuild moduleset that can be used to build/update openssl.

#### Usage:

Now use it like this:
    
~~~~
$ jhbuild -m file://$(pwd)/openssl.modules build openssl
~~~~
