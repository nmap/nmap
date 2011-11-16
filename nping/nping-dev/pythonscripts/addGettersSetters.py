


o = open("OutputGettersSetters.txt","a") 

classname = raw_input("Class Name: ")
my_range = raw_input("Number of attrs: ")
methname= []
attrname = []
attrtype= []

for i in range( int(my_range) ):
    methname.append( raw_input("Method Name:") )
    attrname.append ( raw_input("Attr Name: ") )
    attrtype.append(raw_input("Attr type:") )

    for line in open("TemplateGettersSetters.txt"):
        line = line.replace("METHNAME",methname[i])
        line = line.replace("TYPE",attrtype[i])
        line = line.replace("ATTRNAME",attrname[i])
        line = line.replace("CLASSNAME",classname)
        o.write(line) 


o.close()



