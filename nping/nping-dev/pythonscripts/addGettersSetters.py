from six.moves import range
from six.moves import input



o = open("OutputGettersSetters.txt","a") 

classname = input("Class Name: ")
my_range = input("Number of attrs: ")
methname= []
attrname = []
attrtype= []

for i in range( int(my_range) ):
    methname.append( input("Method Name:") )
    attrname.append ( input("Attr Name: ") )
    attrtype.append(input("Attr type:") )

    for line in open("TemplateGettersSetters.txt"):
        line = line.replace("METHNAME",methname[i])
        line = line.replace("TYPE",attrtype[i])
        line = line.replace("ATTRNAME",attrname[i])
        line = line.replace("CLASSNAME",classname)
        o.write(line) 


o.close()



