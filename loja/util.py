"""Entradas estruturadas e cálculo limitado, sem execução de código."""
import ast
import json
import operator

import yaml


def calcular(expression):
    if len(expression) > 64:
        raise ValueError('Expressão muito longa.')
    try:
        tree = ast.parse(expression, mode='eval')
    except SyntaxError:
        raise ValueError('Expressão inválida.') from None
    operators = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv}

    def visit(node, depth=0):
        if depth > 8:
            raise ValueError('Expressão complexa demais.')
        if isinstance(node, ast.Constant) and type(node.value) in (int, float):
            value = node.value
        elif isinstance(node, ast.BinOp) and type(node.op) in operators:
            try:
                value = operators[type(node.op)](visit(node.left, depth+1), visit(node.right, depth+1))
            except (ZeroDivisionError, OverflowError):
                raise ValueError('Operação inválida.') from None
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
            value = visit(node.operand, depth+1) * (-1 if isinstance(node.op, ast.USub) else 1)
        else:
            raise ValueError('Operação não permitida.')
        if not -1000000 <= value <= 1000000:
            raise ValueError('Resultado fora do limite.')
        return value
    return visit(tree.body)


def importar_carrinho(dados):
    try:
        result = json.loads(dados)
    except (ValueError, UnicodeDecodeError):
        raise ValueError('Use JSON válido.') from None
    if not isinstance(result, dict) or set(result) != {'itens'} or not isinstance(result['itens'], list) or len(result['itens']) > 100:
        raise ValueError('Carrinho inválido.')
    for item in result['itens']:
        if not isinstance(item, dict) or set(item) != {'id','quantidade'}:
            raise ValueError('Item inválido.')
        if type(item['id']) is not int or type(item['quantidade']) is not int or not (item['id'] > 0 and 1 <= item['quantidade'] <= 100):
            raise ValueError('Item inválido.')
    return result


def ler_config(texto):
    if len(texto) > 1024:
        raise ValueError('Configuração muito grande.')
    try:
        result = yaml.safe_load(texto)
    except yaml.YAMLError:
        raise ValueError('YAML inválido.') from None
    if not isinstance(result, dict) or set(result) - {'tema','idioma'}:
        raise ValueError('Chave de configuração inválida.')
    if any(not isinstance(value, str) or len(value) > 40 for value in result.values()):
        raise ValueError('Valor de configuração inválido.')
    return result
