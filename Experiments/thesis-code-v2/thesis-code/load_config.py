#!/usr/bin/python

import json

# Declare files
CONFIG =            "config.json"

MODEL_MAIN_EBF =     "models/main_ebpf.model.rs"
MODEL_MAIN =         "models/main.model.rs"
MODEL_CONDITIONS =   "models/conditions.model.rs"
MODEL_COMMON =       "models/lib.model.rs"

OUTPUT_MAIN_EBPF =  "thesis-code-ebpf/src/main.rs"
OUTPUT_MAIN =       "thesis-code/src/main.rs"
OUTPUT_CONDITIONS = "thesis-code-ebpf/src/conditions.rs"
OUTPUT_COMMON =     "thesis-code-common/src/lib.rs"

check_indexes = {}

# Files data

new_main_ebpf   = open(MODEL_MAIN_EBF,"r").read()
new_main        = open(MODEL_MAIN,"r").read()
new_conditions  = open(MODEL_CONDITIONS,"r").read()
new_common      = open(MODEL_COMMON,"r").read()


# Create the hook for each kfunction in ebpf file 
def gen_kprobes(kfunctions):
    global new_main_ebpf
    placeholder = "/* $KPROBES_PLACEHOLDER$ */"

    model = open("models/kprobe.model","r").read()

    code = "\n\n".join([model.replace("{$kfunction$}", kfunction) for kfunction in kfunctions])

    new_main_ebpf = new_main_ebpf.replace(placeholder, code)
    return



# Declare the hook in main file
def declare_hook(kfunctions):
    global new_main
    placeholder = "/* $KFUNCTIONS_PLACEHOLDER$ */"

    code = ", ".join([f'"{f}"' for f in kfunctions])

    new_main = new_main.replace(placeholder, code)

    return


def set_condition_types(condition_lists):
    global new_common
    placeholder = "/* $CONDITION_TYPES_PLACEHOLDER$ */"
    code = ",\n\t".join(list(condition_lists.keys()))
    new_common = new_common.replace(placeholder, code)
    return

# Fill the graph with node in main file
def fill_graph(config, condition_lists):
    global new_main
    placeholder = "/* $GRAPH_FILL_PLACEHOLDER$ */"

    graph = config['graph']

    entries = []

    for node in graph:
        node_id = str(node['id'])
        node_type = node['type']
        condition_type = node['condition_type']
        check_num = str(condition_lists[condition_type].index(f"f{node_id}"))
        children = ','.join([str(c) for c in node['children']])
        parents = ','.join([str(p) for p in node['parents']])
        kfunction = node['kfunction']

        model = open("models/add_graph_entry.model","r").read() \
            .replace("{$ID$}", node_id) \
            .replace("{$NODE_TYPE$}", node_type) \
            .replace("{$CONDITION_TYPE$}", condition_type) \
            .replace("{$CHECK_NUM$}", check_num) \
            .replace("{$CHILDREN$}", children) \
            .replace("{$PARENTS$}", parents) \
            .replace("{$KFUNCTION$}", kfunction) 

        entries.append(model)
    
    code = "\n".join(entries)
    new_main = new_main.replace(placeholder, code)
    return

def gen_check_funcs(config):
    global new_conditions
    placeholder = "/* $CHECK_FUNCS_PLACEHOLDER$ */"

    graph = config['graph']

    functions = []

    conditions_lists = {}

    for node in graph:
        func_name = f"f{node['id']}"
        condition_type = node['condition_type']
        condition = node['condition']
        args = get_args(condition_type)

        if condition_type in conditions_lists:
            conditions_lists[condition_type].append(func_name)
        else:
            conditions_lists[condition_type] = [func_name]

        model = open("models/check_function.model","r").read() \
            .replace("{$NAME$}", func_name) \
            .replace("{$ARGS$}", args) \
            .replace("{$CONDITION$}", condition)
        
        functions.append(model)

    code = "\n\n".join(functions)

    lists = []
    for condition_type in list(conditions_lists.keys()):
        size = len(conditions_lists[condition_type])
        args = get_args(condition_type)
        args_type = ', '.join([param.split(':')[1].strip() for param in  args.split(',')])
        functions = ", ".join(conditions_lists[condition_type])
        model = open("models/check_list.model", "r").read() \
            .replace("{$CONDITION_TYPE$}", condition_type) \
            .replace("{$ARGS_TYPE$}", args_type) \
            .replace("{$SIZE$}", str(size)) \
            .replace("{$FUNCTIONS$}", functions)
        
        lists.append(model)
    
    code += "\n\n" + "\n".join(lists)

    new_conditions = new_conditions.replace(placeholder, code)
    return

def gen_checks(condition_lists):
    global new_conditions
    placeholder = "/* $CHECK_PLACEHOLDER$ */"

    checks = []
    for condition_type in condition_lists.keys():
        args = get_args(condition_type)
        params = ', '.join([param.split(':')[0].strip() for param in  args.split(',')])
        num_check = []
        for i in range(len(condition_lists[condition_type])):
            num_check.append("else if num == " + str(i) + " { CHECK_TYPE_" + condition_type + "[" + str(i) + "](" + params + ") }")
        model = open("models/checks_conditions.model","r").read() \
            .replace("{$CONDITION_TYPE$}", condition_type) \
            .replace("{$NUM_CHECK$}", "\n\t\t".join(num_check))
        checks.append(model)
    
    code = open("models/check.model","r").read().replace("{$CONDITIONS$}", "\n".join(checks)[9:])

    new_conditions = new_conditions.replace(placeholder, code)
    return

def set_graph_size(config):
    global new_common
    placeholder = "/* $CONDITION_NUM_PLACEHOLDER$ */"
    size = len(config['graph'])
    code = f"pub const CONDITION_NUM: usize = {size};"
    new_common = new_common.replace(placeholder, code)
    return

def gen_init_graph(config):
    global new_common
    placeholder = "/* $BASED_GRAPH_PLACEHOLDER$ */"
    status = ["WAITING" if node['type'] == "PRIMARY" else "UNREACHABLE" for node in config['graph']]
    code = f"[{', '.join(status)}]"
    new_common = new_common.replace(placeholder, code)
    return

# Main program
def main():
    config = json.load(open(CONFIG,'r'))
    # generate hooks
    kfunctions = get_kfunctions(config)
    condition_lists = get_condition_lists(config)

    gen_kprobes(kfunctions)
    declare_hook(kfunctions)
    set_condition_types(condition_lists)
    fill_graph(config, condition_lists)
    gen_check_funcs(config)
    gen_checks(condition_lists)
    set_graph_size(config)
    gen_init_graph(config)

    save_files()
    
    return

# Helpers

# Get the kfunctions list from the config
def get_kfunctions(config):
    functions = [node['kfunction'] for node in config['graph']]
    return list(dict.fromkeys(functions))

# Get the dictionnary of conditions types to check_functions name
def get_condition_lists(config):
    graph = config['graph']

    conditions_lists = {}

    for node in graph:
        func_name = f"f{node['id']}"
        condition_type = node['condition_type']

        if condition_type in conditions_lists:
            conditions_lists[condition_type].append(func_name)
        else:
            conditions_lists[condition_type] = [func_name]
    
    return conditions_lists


# Get the args for a given condition type
def get_args(condition_type):
    if condition_type == "CONTEXT":
        return ("ctx: &ProbeContext")
    elif condition_type == "PID":
        return "pid: u32"
    elif condition_type == "COUNT":
        return "count: u32"


def save_files():
    open(OUTPUT_MAIN_EBPF, "w").write(new_main_ebpf)
    open(OUTPUT_MAIN, "w").write(new_main)
    open(OUTPUT_CONDITIONS, "w").write(new_conditions)
    open(OUTPUT_COMMON, "w").write(new_common)


if __name__ == "__main__":
    main()