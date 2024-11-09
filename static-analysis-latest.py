import os
import sys
import javalang
import traceback

def find_java_files(root_dir):
    """Recursively find all Java files in the given directory."""
    java_files = []
    for root, _, files in os.walk(root_dir):
        for file in files:
            if file.endswith('.java'):
                full_path = os.path.join(root, file)
                java_files.append(full_path)
    return java_files

def detect_coarse_grained_synchronization(tree, filename, code_lines, results):
    """Detect classes with multiple synchronized methods."""
    for _, node in tree.filter(javalang.tree.ClassDeclaration):
        class_name = node.name
        synchronized_methods = []
        method_nodes = []  # Initialize method_nodes before use
        for method in node.methods:
            if 'synchronized' in method.modifiers:
                synchronized_methods.append(method.name)
                method_nodes.append(method)
        if len(synchronized_methods) > 1:
            print(f"Detected!!![Synchronized Method Anti-Pattern] In file '{filename}', "
                  f"class '{class_name}' has multiple synchronized methods: {synchronized_methods}")

            message = (f"Detected!!![Synchronized Method Anti-Pattern] In file '{filename}', "
                       f"class '{class_name}' has multiple synchronized methods: {synchronized_methods}")
            recommendation = (f"Recommendation: Consider using fine-grained synchronization to reduce contention. Instead of synchronizing the entire methods: {synchronized_methods}, synchronize only the critical section of the code that accesses shared resources. This can help reduce contention and improve performance.")

            # Extract code snippet: collect the synchronized methods
            snippets = []
            for method in method_nodes:
                if method.position:
                    start_line = method.position.line - 1  # Line numbers are 1-based
                    end_line = start_line + 10  # Adjust as needed
                    snippet = '\n'.join(code_lines[start_line:end_line])
                    snippets.append(snippet)
                else:
                    # Handle cases where position might be None
                    snippets.append(f"Method '{method.name}' code not available.")
            code_snippet = '\n\n'.join(snippets)

            # Append to results
            results.append({
                'Code Snippet': code_snippet,
                'Detection Message': message,
                'Recommendation': recommendation
            })

            # Save this message to output.txt file
            with open('output.txt', 'a') as f:
                f.write(message)
                f.write('\n')
                f.write(recommendation)
                f.write('\n\n\n')

def detect_overly_split_locks(tree, filename, code_lines, results):
    """Detect methods with multiple synchronized blocks locking the same object."""
    for _, method in tree.filter(javalang.tree.MethodDeclaration):
        method_name = method.name
        lock_usage = {}        # Dictionary to track locks and their occurrences
        lock_positions = {}    # Initialize lock_positions here

        def traverse(node):
            if isinstance(node, javalang.tree.SynchronizedStatement):
                # Try multiple possible attribute names for the lock object
                lock_expr = getattr(node, 'lock', None) or getattr(node, 'expression', None) or getattr(node, 'monitor', None)
                if lock_expr is None:
                    print(f"Could not find lock object in SynchronizedStatement node.")
                    return

                lock_str = None

                # Get the lock expression as a string
                if isinstance(lock_expr, javalang.tree.MemberReference):
                    lock_str = lock_expr.member
                elif isinstance(lock_expr, javalang.tree.Literal):
                    lock_str = lock_expr.value
                elif isinstance(lock_expr, javalang.tree.This):
                    lock_str = 'this'
                elif isinstance(lock_expr, javalang.tree.Identifier):
                    lock_str = lock_expr.name
                elif isinstance(lock_expr, javalang.tree.FieldAccess):
                    lock_str = lock_expr.field
                else:
                    # For other types, attempt to get a generic string representation
                    lock_str = str(lock_expr)

                if lock_str:
                    lock_usage.setdefault(lock_str, 0)
                    lock_usage[lock_str] += 1
                    # Store the position of this synchronized block
                    if lock_str not in lock_positions:
                        lock_positions[lock_str] = []
                    lock_positions[lock_str].append(node.position)

                # Traverse the statements inside the synchronized block
                if isinstance(node.block, list):
                    for child in node.block:
                        traverse(child)
                else:
                    for child in node.block.statements:
                        traverse(child)
            elif isinstance(node, javalang.tree.Node):
                for child in node.children:
                    if isinstance(child, javalang.tree.Node):
                        traverse(child)
                    elif isinstance(child, list):
                        for item in child:
                            if isinstance(item, javalang.tree.Node):
                                traverse(item)

        if method.body:
            for statement in method.body:
                traverse(statement)

        # Check for locks used more than once
        overly_split_locks = [lock for lock, count in lock_usage.items() if count > 1]
        if overly_split_locks:
            print(f"Detected !!! [Overly Split Locks] In file '{filename}', method '{method_name}' has multiple synchronized blocks locking the same object(s): {overly_split_locks}")
            message = (f"Detected !!! [Overly Split Locks] In file '{filename}', method '{method_name}' has multiple synchronized blocks locking the same object(s): {overly_split_locks}")
            recommendation = ("Recommendation: Consider merging the split locks into more cohesive synchronized blocks to reduce overhead and potential contention.")

            # Extract code snippets for the synchronized blocks using overly split locks
            snippets = []
            for lock in overly_split_locks:
                positions = lock_positions.get(lock, [])
                for pos in positions:
                    if pos:
                        start_line = pos.line - 1  # zero-based index
                        end_line = start_line + 10  # Adjust as needed
                        snippet = '\n'.join(code_lines[start_line:end_line])
                        snippets.append(snippet)
            code_snippet = '\n\n'.join(snippets)

            # Append to results
            results.append({
                'Code Snippet': code_snippet,
                'Detection Message': message,
                'Recommendation': recommendation
            })

            # Append to output.txt
            with open('output.txt', 'a') as f:
                f.write(message)
                f.write('\n')
                f.write(recommendation)
                f.write('\n\n\n')


def contains_loop(node):
    """Recursively check if a node or any of its descendants is a loop construct.
    Returns the loop node if found, otherwise returns None."""
    if node is None:
        return None

    if isinstance(node, list):
        for item in node:
            result = contains_loop(item)
            if result is not None:
                return result
        return None  # Return None after checking all items

    print(f"Visiting node: {type(node).__name__}")

    if isinstance(node, (javalang.tree.ForStatement,
                         javalang.tree.WhileStatement,
                         javalang.tree.DoStatement)):
        print(f"Found loop: {type(node).__name__} at line {node.position}")
        return node  # Return the loop node

    elif hasattr(node, 'children') and node.children:
        for child in node.children:
            result = contains_loop(child)
            if result is not None:
                return result

    return None

def detect_loop_inside_critical(tree, filename, code_lines, results):
    """Detect loops that are entirely within synchronized blocks or methods."""
    print(f"Analyzing file: {filename}")
    # Analyze synchronized methods
    for _, method in tree.filter(javalang.tree.MethodDeclaration):
        if 'synchronized' in method.modifiers:
            method_name = method.name
            print(f"Found synchronized method: {method_name}")
            loop_node = None  # Initialize loop_node
            # Check if the method body contains loops
            if method.body:
                loop_node = contains_loop(method.body)
            if loop_node:
                # Anti-pattern detected
                message = (f"Detected!! [Loop Inside Critical Section] In file '{filename}', synchronized method "
                           f"'{method_name}' contains a loop inside the synchronized context.")
                recommendation = ("Recommendation: Consider refactoring the loop to minimize the synchronized section "
                                  "or parallelize it to improve performance.")
                print(message)
                # Extract code snippet (synchronized method including the loop)
                if method.position and loop_node.position:
                    start_line = method.position.line - 1  # Start of the synchronized method
                    end_line = loop_node.position.line - 1 + 5  # Include 5 lines after the loop
                    end_line = min(end_line, len(code_lines))
                    code_snippet = '\n'.join(code_lines[start_line:end_line])
                elif method.position:
                    start_line = method.position.line - 1
                    end_line = start_line + 20  # Adjust as needed
                    end_line = min(end_line, len(code_lines))
                    code_snippet = '\n'.join(code_lines[start_line:end_line])
                else:
                    code_snippet = ''  # Could not extract code snippet

                # Append to results
                results.append({
                    'Code Snippet': code_snippet,
                    'Detection Message': message,
                    'Recommendation': recommendation
                })

                # Append to output.txt
                with open('output.txt', 'a') as f:
                    f.write(message + '\n')
                    f.write(recommendation + '\n\n')

    # Analyze synchronized blocks
    for path, node in tree.filter(javalang.tree.SynchronizedStatement):
        print(f"Found synchronized block at line {node.position}")
        loop_node = None  # Initialize loop_node
        # Check if the synchronized block contains loops
        loop_node = contains_loop(node.block)
        if loop_node:
            # Get the parent method name if available
            method_name = None
            for ancestor in reversed(path):
                if isinstance(ancestor, javalang.tree.MethodDeclaration):
                    method_name = ancestor.name
                    break
            message = (f"Detected!! [Loop Inside Critical Section] In file '{filename}', synchronized block "
                       f"contains a loop inside the synchronized context.")
            if method_name:
                message += f" (Method: {method_name})"
            recommendation = ("Recommendation: Consider refactoring the loop to minimize the synchronized section "
                              "or parallelize it to improve performance.")
            print(message)

            # Extract code snippet (synchronized block including the loop)
            if node.position and loop_node.position:
                start_line = node.position.line - 1  # Start of the synchronized block
                end_line = loop_node.position.line - 1 + 5  # Include 5 lines after the loop
                end_line = min(end_line, len(code_lines))
                code_snippet = '\n'.join(code_lines[start_line:end_line])
            elif node.position:
                start_line = node.position.line - 1
                end_line = start_line + 20  # Adjust as needed
                end_line = min(end_line, len(code_lines))
                code_snippet = '\n'.join(code_lines[start_line:end_line])
            else:
                code_snippet = ''  # Could not extract code snippet

            # Append to results
            results.append({
                'Code Snippet': code_snippet,
                'Detection Message': message,
                'Recommendation': recommendation
            })

            # Append to output.txt
            with open('output.txt', 'a') as f:
                f.write(message + '\n')
                f.write(recommendation + '\n\n')
        else:
            print("No loop found inside synchronized block")



def contains_synchronized_block(node):
    """Recursively check if a node or any of its descendants is a synchronized block.
    Returns the synchronized block node if found, otherwise returns None."""
    if node is None:
        return None

    if isinstance(node, javalang.tree.SynchronizedStatement):
        print(f"Found synchronized block at line {node.position}")
        return node  # Return the synchronized block node

    if isinstance(node, list):
        for item in node:
            result = contains_synchronized_block(item)
            if result is not None:
                return result
        return None

    print(f"Visiting node: {type(node).__name__}")

    if hasattr(node, 'children'):
        for child in node.children:
            result = contains_synchronized_block(child)
            if result is not None:
                return result
    return None


def detect_loop_outside_critical(tree, filename, code_lines, results):
    """Detect loops that contain synchronized blocks inside them."""
    print(f"Analyzing file: {filename}")
    for _, method in tree.filter(javalang.tree.MethodDeclaration):
        method_name = method.name
        print(f"Analyzing method: {method_name}")

        def traverse(node):
            if node is None:
                return
            if isinstance(node, (javalang.tree.ForStatement,
                                 javalang.tree.WhileStatement,
                                 javalang.tree.DoStatement)):
                loop_type = type(node).__name__
                print(f"Found loop: {loop_type} at line {getattr(node.position, 'line', 'unknown')}")

                # Check if the loop body contains a synchronized block
                sync_node = contains_synchronized_block(node.body)
                if sync_node:
                    # Anti-pattern detected
                    message = (f"Detected!! [Loop Outside Critical Section] In file '{filename}', method '{method_name}' "
                               f"contains a loop ({loop_type}) with a synchronized block inside.")
                    recommendation = ("Recommendation: Consider moving the synchronized block outside the loop if possible "
                                      "or minimizing the synchronized operations to reduce lock contention.")
                    print(message)

                    # Extract code snippet including both loop and synchronized block
                    if node.position and sync_node.position:
                        start_line = node.position.line - 1  # Start of the loop
                        end_line = sync_node.position.line - 1 + 5  # Include 5 lines after the synchronized block
                        end_line = min(end_line, len(code_lines))  # Ensure end_line is within bounds
                        code_snippet = '\n'.join(code_lines[start_line:end_line])
                    elif node.position:
                        start_line = node.position.line - 1
                        end_line = start_line + 20  # Default snippet length
                        end_line = min(end_line, len(code_lines))
                        code_snippet = '\n'.join(code_lines[start_line:end_line])
                    else:
                        code_snippet = ''  # Could not extract code snippet

                    # Append to results
                    results.append({
                        'Code Snippet': code_snippet,
                        'Detection Message': message,
                        'Recommendation': recommendation
                    })

                    # Append to output.txt
                    with open('output.txt', 'a') as f:
                        f.write(message + '\n')
                        f.write(recommendation + '\n\n')
                else:
                    print("No synchronized block found inside loop")

                # Continue traversing the loop body
                traverse(node.body)
            elif isinstance(node, list):
                for child in node:
                    traverse(child)
            elif hasattr(node, 'children'):
                for child in node.children:
                    traverse(child)

        # Start traversal from the method body
        if method.body:
            for statement in method.body:
                traverse(statement)


def detect_unified_locking(tree, filename, code_lines, results):
    """Detect the Unified Locking anti-pattern where a single lock is used for multiple unrelated resources."""
    print(f"Analyzing file: {filename}")

    # Collect information about synchronized blocks
    lock_usage = {}       # Maps lock names to a set of methods and resources they protect
    lock_positions = {}   # Initialize lock_positions here

    # Use AST traversal to find all SynchronizedStatement nodes
    for path, sync_block in tree.filter(javalang.tree.SynchronizedStatement):
        # Get the method in which this synchronized block is located
        method_name = None
        for node in reversed(path):
            if isinstance(node, javalang.tree.MethodDeclaration):
                method_name = node.name
                break
        if not method_name:
            continue  # Skip if we can't find the method name

        # Get the lock name
        lock_name = get_lock_name(sync_block)
        if not lock_name:
            continue

        # Get modified resources within the synchronized block
        resources = get_modified_resources(sync_block.block)

        # Store the synchronized block position
        if lock_name not in lock_positions:
            lock_positions[lock_name] = []
        lock_positions[lock_name].append(sync_block.position)

        # Update lock usage information
        if lock_name not in lock_usage:
            lock_usage[lock_name] = {'methods': set(), 'resources': set()}
        lock_usage[lock_name]['methods'].add(method_name)
        lock_usage[lock_name]['resources'].update(resources)

    # Identify locks used in multiple methods protecting different resources
    for lock_name, usage in lock_usage.items():
        if len(usage['methods']) > 1 and len(usage['resources']) > 1:
            # Anti-pattern detected
            methods = ', '.join(usage['methods'])
            resources = ', '.join(usage['resources'])
            message = (f"Detected!! [Unified Locking] In file '{filename}', the lock '{lock_name}' is used in multiple methods "
                       f"({methods}) to protect different resources ({resources}).")
            recommendation = ("Recommendation: Use separate locks for different resources to reduce contention "
                              "and improve concurrency.")
            print(message)

            # Extract code snippets for the synchronized blocks using the lock
            snippets = []
            positions = lock_positions.get(lock_name, [])
            for pos in positions:
                if pos:
                    start_line = pos.line - 1  # zero-based index
                    end_line = start_line + 10  # Adjust as needed
                    snippet = '\n'.join(code_lines[start_line:end_line])
                    snippets.append(snippet)
            code_snippet = '\n\n'.join(snippets)

            # Append to results
            results.append({
                'Code Snippet': code_snippet,
                'Detection Message': message,
                'Recommendation': recommendation
            })

            # Append to output.txt
            with open('output.txt', 'a') as f:
                f.write(message + '\n')
                f.write(recommendation + '\n\n')

def get_lock_name(sync_block):
    """Extract the lock name used in a synchronized block."""
    if hasattr(sync_block, 'lock'):
        lock = sync_block.lock
    else:
        print("SynchronizedStatement has no 'lock' attribute")
        return None
    # Proceed to extract the lock name
    if isinstance(lock, javalang.tree.MemberReference):
        return lock.member
    elif isinstance(lock, javalang.tree.This):
        return 'this'
    elif isinstance(lock, javalang.tree.Literal):
        return lock.value
    elif isinstance(lock, javalang.tree.Identifier):
        return lock.member
    elif isinstance(lock, javalang.tree.VariableDeclaratorId):
        return lock.name
    elif isinstance(lock, javalang.tree.SimpleReference):
        return lock.name
    else:
        print(f"Unknown lock type: {type(lock)}")
        return None

def get_modified_resources(block):
    """Extract the resource names (variables) that are modified within a block."""
    resources = set()

    def traverse(node):
        if node is None:
            return
        if isinstance(node, javalang.tree.Assignment):
            # Left-hand side of the assignment
            lhs = node.expressionl
            if isinstance(lhs, javalang.tree.MemberReference):
                resources.add(lhs.member)
            elif isinstance(lhs, javalang.tree.Identifier):
                resources.add(lhs.member)
        elif isinstance(node, javalang.tree.MethodInvocation):
            # Method calls may modify resources; collect method names
            resources.add(node.member)
        elif isinstance(node, list):
            for item in node:
                traverse(item)
        elif hasattr(node, 'children'):
            for child in node.children:
                traverse(child)

    traverse(block)
    return resources


def detect_same_lock(tree, filename, code_lines, results):
    """Detect the Same Lock anti-pattern where multiple critical sections synchronize using the same mutable object."""
    print(f"Analyzing file: {filename}")

    # Collect information about synchronized blocks
    lock_usage = {}       # Maps lock names to a list of methods where it's used
    lock_positions = {}   # Initialize lock_positions here

    # Use AST traversal to find all SynchronizedStatement nodes
    for path, sync_block in tree.filter(javalang.tree.SynchronizedStatement):
        # Get the method in which this synchronized block is located
        method_name = None
        for node in reversed(path):
            if isinstance(node, javalang.tree.MethodDeclaration):
                method_name = node.name
                break
        if not method_name:
            continue  # Skip if we can't find the method name

        # Get the lock name
        lock_name = get_lock_name_same_lock(sync_block)
        if not lock_name:
            continue

        # Check if the lock is a mutable field of the class
        if is_mutable_field(tree, lock_name):
            if lock_name not in lock_usage:
                lock_usage[lock_name] = set()
                lock_positions[lock_name] = []
            lock_usage[lock_name].add(method_name)
            # Store the position of this synchronized block
            lock_positions[lock_name].append(sync_block.position)

    # Identify locks used in multiple methods
    for lock_name, methods in lock_usage.items():
        if len(methods) > 1:
            # Anti-pattern detected
            methods_list = ', '.join(methods)
            message = (f"Detected!!! [Same Lock] In file '{filename}', the lock '{lock_name}' (a mutable field) is used in multiple methods "
                       f"({methods_list}) for synchronization, which may lead to contention and thread safety issues.")
            recommendation = ("Recommendation: Implement an Atomic type or use dedicated lock objects instead of synchronizing on mutable fields "
                              "to avoid contention and potential thread safety issues.")
            print(message)

            # Extract code snippets for the synchronized blocks using the same mutable lock
            snippets = []
            positions = lock_positions.get(lock_name, [])
            for pos in positions:
                if pos:
                    start_line = pos.line - 1  # zero-based index
                    end_line = start_line + 10  # Adjust as needed
                    snippet = '\n'.join(code_lines[start_line:end_line])
                    snippets.append(snippet)
            code_snippet = '\n\n'.join(snippets)

            # Append to results
            results.append({
                'Code Snippet': code_snippet,
                'Detection Message': message,
                'Recommendation': recommendation
            })

            # Append to output.txt
            with open('output.txt', 'a') as f:
                f.write(message + '\n')
                f.write(recommendation + '\n\n')


def get_lock_name_same_lock(sync_block):
    """Extract the lock name used in a synchronized block for Same Lock detection."""
    if hasattr(sync_block, 'lock'):
        lock = sync_block.lock
    else:
        print("SynchronizedStatement has no 'lock' attribute")
        return None

    # Extract the lock name
    if isinstance(lock, javalang.tree.MemberReference):
        return lock.member
    elif isinstance(lock, javalang.tree.This):
        return 'this'
    elif isinstance(lock, javalang.tree.Literal):
        return lock.value
    elif isinstance(lock, javalang.tree.Identifier):
        return lock.value
    elif isinstance(lock, javalang.tree.VariableDeclaratorId):
        return lock.name
    elif isinstance(lock, javalang.tree.SimpleReference):
        return lock.name
    else:
        print(f"Unknown lock type: {type(lock)}")
        return None

def is_mutable_field(tree, lock_name):
    """Check if the lock is a mutable field of the class."""
    # Search for field declarations matching the lock name
    for _, node in tree.filter(javalang.tree.FieldDeclaration):
        for declarator in node.declarators:
            if declarator.name == lock_name:
                # Check if the type is mutable
                field_type = node.type
                if isinstance(field_type, javalang.tree.BasicType):
                    # Primitive types cannot be synchronized on
                    return True
                elif isinstance(field_type, javalang.tree.ReferenceType):
                    # Check if it's an immutable type
                    type_name = '.'.join(field_type.name) if isinstance(field_type.name, list) else field_type.name
                    immutable_types = ['String', 'Integer', 'Float', 'Double', 'Boolean', 'Character', 'Byte', 'Short', 'Long']
                    if type_name in immutable_types:
                        # Immutable types
                        return False
                    else:
                        # Assume mutable if not in the list of known immutable types
                        return True
                else:
                    return True
    return False  # Not a field or not mutable

def write_results_to_csv(results):
    """Writes the collected results to a CSV file."""
    import csv
    if not results:
        print("No results to write to CSV.")
        return
    with open('anti_patterns.csv', 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['Code Snippet', 'Detection Message', 'Recommendation']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(result)
    print(f"CSV file 'anti_patterns.csv' has been created with {len(results)} entries.")


def count_anti_patterns(output_file='output.txt'):
    """Counts the number of occurrences of each anti-pattern in the output file."""
    import re
    anti_pattern_counts = {}

    # Regular expression to match the anti-pattern name after 'Detected' and within square brackets
    pattern = re.compile(r'Detected.*?\[([^\]]+)\]')

    try:
        with open(output_file, 'r', encoding='utf-8') as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    anti_pattern_name = match.group(1).strip()
                    # Increment the count for this anti-pattern
                    anti_pattern_counts[anti_pattern_name] = anti_pattern_counts.get(anti_pattern_name, 0) + 1
    except FileNotFoundError:
        print(f"The file '{output_file}' does not exist.")
        return

    # Print the counts
    print("Anti-pattern counts:")
    for anti_pattern, count in anti_pattern_counts.items():
        print(f"{anti_pattern}: {count}")


def main(input_folder):
    """Main function to process Java files and detect anti-patterns."""
    java_files = find_java_files(input_folder)
    results = []  # List to store results for CSV
    if not java_files:
        print(f"No Java files found in '{input_folder}'.")
    else:
        print(f"Found {len(java_files)} Java files.")
    for java_file in java_files:
        print(f"Processing file: {java_file}")
        try:
            with open(java_file, 'r', encoding='utf-8') as f:
                code = f.read()
            code_lines = code.split('\n')
            tree = javalang.parse.parse(code)
            detect_coarse_grained_synchronization(tree, java_file, code_lines, results)
            #detect_nested_locks(tree, java_file, code_lines, results)
            detect_overly_split_locks(tree, java_file, code_lines, results)
            #detect_reentrance_lockout(tree, java_file, code_lines, results)
            detect_loop_inside_critical(tree, java_file, code_lines, results)
            detect_loop_outside_critical(tree, java_file, code_lines, results)
            detect_unified_locking(tree, java_file, code_lines, results)
            detect_same_lock(tree, java_file, code_lines, results)
        except Exception as e:
            print(f"Failed to parse '{java_file}': {e}")
            traceback.print_exc()
    # After processing all files, write results to CSV
    if results:
        print(f"Total results collected: {len(results)}")
    else:
        print("No anti-patterns detected.")
    write_results_to_csv(results)
    count_anti_patterns('output.txt')

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python static_analysis_tool.py <input_folder>")
    else:
        input_folder = sys.argv[1]
        main(input_folder)
