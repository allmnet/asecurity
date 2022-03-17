a = 1

def sum():
    global a
    a = 2
    b = 2
    c = a+b
    print(c)

sum()

print(a)