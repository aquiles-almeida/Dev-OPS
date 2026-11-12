"""Worker sem pickle e sem execução de comandos de shell."""
import json
from pathlib import Path

from PIL import Image


def processar(mensagem):
    if len(mensagem) > 65536:
        raise ValueError('Mensagem muito grande.')
    task = json.loads(mensagem)
    if not isinstance(task, dict) or set(task) != {'tipo'} or task['tipo'] not in {'emitir_nfe','miniatura'}:
        raise ValueError('Tarefa inválida.')
    return task['tipo']


def miniatura(arquivo, base='/tmp/ct-imagens'):
    root = Path(base).resolve()
    path = (root / arquivo).resolve()
    if not path.is_relative_to(root) or path.suffix.lower() not in {'.jpg','.jpeg','.png'}:
        raise ValueError('Arquivo inválido.')
    with Image.open(path) as image:
        image.thumbnail((200,200))
        destination = root / 'miniatura.png'
        image.save(destination, format='PNG')
    return str(destination)
