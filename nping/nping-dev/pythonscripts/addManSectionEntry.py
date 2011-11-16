
sectionname = raw_input("Section name: ")
hyphname = raw_input("Hyphened name: ")


o = open("OutputMan.txt","a") 
for line in open("man-section-template.xml"):
        line = line.replace("SECTION_NAME",sectionname)
        line = line.replace("SECTION_HYPHENED_NAME",hyphname)
        o.write(line) 


my_range = raw_input("Number of options: ")
optformat = []
optarg= []
optdesc= []
optname= []

for i in range( int(my_range) ):
    optformat.append( raw_input("Option format (--tcp-connect): --") )
    optarg.append ( raw_input("Option arg (portnumber): ") )
    optdesc.append(raw_input("Option Description (TCP Connect Mode):") )
    optname.append(raw_input("Option name (tcp connect): ") )


    for line in open("man-section-entry-template.xml"):
        line = line.replace("OPT_FORMAT",optformat[i])
        if( optarg[i] == ""):
            line = line.replace("OPT_ARG","")
        else:
            line = line.replace("OPT_ARG","<replaceable>"+optarg[i]+"</replaceable>")
        line = line.replace("OPT_DESC",optdesc[i])
        line = line.replace("OPT_NAME",optname[i])
        o.write(line) 

line1="    </variablelist>"
line2="   </refsect1>"
o.write(line1);
o.write(line2);
o.close()



