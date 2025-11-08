from lark import Lark, Transformer

grammar = r"""
?start: stmt+

?stmt: init
     | expr
     | decl

// type name = expr
init: type factor "=" expr -> init | factor "=" expr -> initpd
decl: type factor
// types
?type: "int64"    -> t_int64
     | "int32"    -> t_int32
     | "float64"  -> t_float64
     | "float32"  -> t_float32

// expressions with precedence:
// sum: + -
// term: * /
// factor: literals, vars, parens

?expr: sum

?sum: sum "+" term   -> add
    | sum "-" term   -> sub
    | term

?term: term "*" factor  -> mul
     | term "/" factor  -> div
     | factor

?factor: NUMBER         -> number
       | NAME           -> var
       | "(" expr ")"

// tokens
%import common.NUMBER
%import common.WS
%import common.CNAME -> NAME
%ignore WS
"""

parser = Lark(grammar, start="start")

class AST(Transformer):
    def number(self, items):
        return ("num", int(items[0]))

    def var(self, items):
        return ("var", str(items[0]))

    def add(self, items):
        return ("add", items[0], items[1])

    def sub(self, items):
        return ("sub", items[0], items[1])

    def mul(self, items):
        return ("mul", items[0], items[1])

    def div(self, items):
        return ("div", items[0], items[1])

    def t_int32(self, items):
        return "int32"

    def t_int64(self, items):
        return "int64"

    def t_float64(self, items):
        return "float64"

    def t_float32(self, items):
        return "float32"

    def init(self, items): 
        if(items[1][0] != 'var'): 
            raise(TypeError, "can only assign variables") 
        return ("init", (items[0], items[1]), items[2]) 
    
    def initpd(self, items):
        if(items[0][0] != 'var'): 
            raise(TypeError, "can only assign variables") 
        return ("initpd", items[0], items[1]) 

    def start(self, items):
            return items   
    
    def decl(self, items):
        if(items[1][0] != 'var'):
            raise(TypeError, "can only assign variables")
        return ("decl", items[0], items[1])

if __name__ == "__main__":
    tree = parser.parse("int32 y")
    ast = AST().transform(tree)
    print(ast)
