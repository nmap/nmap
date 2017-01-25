


from builtins import input
from builtins import range
o = open("OutputGettersSetters.txt","a") 

classname = eval(input("Class Name: "))
my_range = eval(input("Number of attrs: "))
methname= []
attrname = []
attrtype= []

for i in range( int(my_range) ):
    methname.append( eval(input("Method Name:")) )
    attrname.append ( eval(input("Attr Name: ")) )
    attrtype.append(eval(input("Attr type:")) )

    for line in open("TemplateGettersSetters.txt"):
        line = line.replace("METHNAME",methname[i])
        line = line.replace("TYPE",attrtype[i])
        line = line.replace("ATTRNAME",attrname[i])
        line = line.replace("CLASSNAME",classname)
        o.write(line) 


o.close()



