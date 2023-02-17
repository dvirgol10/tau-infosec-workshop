import re

keywords = ['auto', 'break', 'case', 'char', 'const', 'continue', 'default', 'do', 'double', 'else', 'enum', 'extern', 'float', 'for', 'goto', 'if', 'int', 'long', 'register', 'return', 'short', 'signed', 'sizeof', 'static', 'struct', 'switch', 'typedef', 'union', 'unsigned', 'void', 'volatile', 'while']
keywords += ['printf', 'malloc', 'pragma', '#include', '#define', '#undef', '#if', '#ifdef', '#ifndef', '#error', '__FILE__', '__LINE__', '__DATE__', '__TIME__', '__TIMESTAMP__']

special_tokens = r"[\{\}\[\]\(\);,\^\#\&\*\-\+\<\>\|]"

special_patterns = [r"\(\)", r"\-\>", r"\/\/", r"\/\*", r"\*\/", r"\&\&", r"\|\|", r"\=\=", r"\!\=", r"\>\=", r"\<\=", r"\>\>", r"\<\<", r"\\n"]

def is_c_code(data, threshold):
    keywords_count = 0
    for keyword in keywords:
        keywords_count += len(re.findall(r"\b{}b".format(keyword), data))

    tokens_count = len(re.findall(special_tokens, data))

    patterns_count = 0
    for pattern in special_patterns:
        patterns_count += len(re.findall(pattern, data))
    
    code_percent = (keywords_count + tokens_count + patterns_count) / float(len(data.split()))

    return code_percent >= threshold


def calculate_num_correct_answers(threshold):
    num_correct_answers = 0

    for i in range(1, 27):
        with open("samples/c_{}.txt".format(i), "r") as f:
            num_correct_answers += is_c_code(f.read(), threshold) == True

    for i in range(1, 27):
        with open("samples/english_{}.txt".format(i), "r") as f:
            num_correct_answers += is_c_code(f.read(), threshold) == False
     
    return num_correct_answers


def main():

    arr_num_correct_answers = []
    precision = 1000
    for i in range(precision):
        threshold = i / float(precision)
        arr_num_correct_answers.append(calculate_num_correct_answers(threshold)) 

    print(arr_num_correct_answers)
    max_value = max(arr_num_correct_answers)
    index = arr_num_correct_answers.index(max_value)
    threshold = index / float(precision)
    print(threshold)


if __name__ == "__main__":
    main()