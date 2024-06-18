#!/usr/bin/python
from language import Node, Graph

# Declare files
GRAPH =              "graph.txt"

# Templates
MODEL_MAIN_EBF =     "models/main_ebpf.model.rs"
MODEL_MAIN =         "models/main.model.rs"
MODEL_CONDITIONS =   "models/conditions.model.rs"
MODEL_COMMON =       "models/lib.model.rs"

# Source files to compile
OUTPUT_MAIN_EBPF =  "thesis-code-ebpf/src/main.rs"
OUTPUT_MAIN =       "thesis-code/src/main.rs"
OUTPUT_CONDITIONS = "thesis-code-ebpf/src/conditions.rs"
OUTPUT_COMMON =     "thesis-code-common/src/lib.rs"

# Files data

new_main_ebpf   = open(MODEL_MAIN_EBF,"r").read()
new_main        = open(MODEL_MAIN,"r").read()
new_conditions  = open(MODEL_CONDITIONS,"r").read()
new_common      = open(MODEL_COMMON,"r").read()


# Create the hook for each kfunction in ebpf file 
def gen_kprobes(graph: Graph):
    global new_main_ebpf
    placeholder = "/* $KPROBES_PLACEHOLDER$ */"

    model = open("models/kprobe.model","r").read()

    kfunctions = []
    for node in graph.nodes:
        if not node.kfunction in kfunctions:
            kfunctions.append(node.kfunction)

    code = "\n\n".join([model.replace("{$kfunction$}", kfunction) for kfunction in kfunctions])

    new_main_ebpf = new_main_ebpf.replace(placeholder, code)
    return



# Declare the hook in main file
def declare_hook(graph: Graph):
    global new_main
    placeholder = "/* $KFUNCTIONS_PLACEHOLDER$ */"

    kfunctions = []
    for node in graph.nodes:
        if not node.kfunction in kfunctions:
            kfunctions.append(node.kfunction)

    code = ", ".join([f'"{kfunction}"' for kfunction in kfunctions])

    new_main = new_main.replace(placeholder, code)

    return

# Fill the graph with node in main file
def fill_graph(graph: Graph):
    global new_main
    placeholder = "/* $GRAPH_FILL_PLACEHOLDER$ */"


    entries = []

    for node in graph.nodes:
        node_id = str(node.node_id)
        node_type = node.node_type.value
        children = ','.join([str(c) for c in node.children])
        parents = ','.join([str(p) for p in node.parents])
        kfunction = node.kfunction

        model = open("models/add_graph_entry.model","r").read() \
            .replace("{$ID$}", node_id) \
            .replace("{$NODE_TYPE$}", node_type) \
            .replace("{$CHILDREN$}", children) \
            .replace("{$PARENTS$}", parents) \
            .replace("{$KFUNCTION$}", kfunction) 

        entries.append(model)
    
    code = "\n".join(entries)
    new_main = new_main.replace(placeholder, code)
    return

def gen_check_funcs(graph: Graph):
    global new_conditions
    placeholder = "/* $CHECK_FUNCS_PLACEHOLDER$ */"

    functions = []
    func_names = []

    for node in graph.nodes:
        func_name = f"f{node.node_id}"
        func_names.append(func_name)
        condition = node.condition

        model = open("models/check_function.model","r").read() \
            .replace("{$NAME$}", func_name) \
            .replace("{$CONDITION$}", condition)
        
        functions.append(model)

    code = "\n\n".join(functions)

    new_conditions = new_conditions.replace(placeholder, code)
    return

def gen_checks(graph: Graph):
    global new_conditions
    placeholder = "/* $CHECK_PLACEHOLDER$ */"

    conditions = "if id == "
    conditions += "\telse if id == ".join([f"{node.node_id} {{ f{node.node_id}(ctx, pid, count) }}\n" for node in graph.nodes])
    
    code = open("models/check.model","r").read().replace("{$CONDITIONS$}", conditions)

    new_conditions = new_conditions.replace(placeholder, code)
    return

def set_graph_size(graph: Graph):
    global new_common
    placeholder = "/* $CONDITION_NUM_PLACEHOLDER$ */"
    code = f"pub const CONDITION_NUM: usize = {graph.size};"
    new_common = new_common.replace(placeholder, code)
    return

def gen_init_graph(graph: Graph):
    global new_common
    placeholder = "/* $BASED_GRAPH_PLACEHOLDER$ */"
    status = ["WAITING" if node.node_type.value == "PRIMARY" else "UNREACHABLE" for node in graph.nodes]
    code = f"[{', '.join(status)}]"
    new_common = new_common.replace(placeholder, code)
    return

# Main program
def main():
    graph = Graph()
    graph.load_file(GRAPH)
    graph.check_graph()
    # generate hooks

    gen_kprobes(graph)
    declare_hook(graph)
    fill_graph(graph)
    gen_check_funcs(graph)
    gen_checks(graph)
    set_graph_size(graph)
    gen_init_graph(graph)

    save_files()
    
    return

# Helpers

def save_files():
    open(OUTPUT_MAIN_EBPF, "w").write(new_main_ebpf)
    open(OUTPUT_MAIN, "w").write(new_main)
    open(OUTPUT_CONDITIONS, "w").write(new_conditions)
    open(OUTPUT_COMMON, "w").write(new_common)


if __name__ == "__main__":
    main()