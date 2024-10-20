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

def detect_coarse_grained_synchronization(tree, filename):
    """Detect classes with multiple synchronized methods."""
    for _, node in tree.filter(javalang.tree.ClassDeclaration):
        class_name = node.name
        synchronized_methods = []
        for method in node.methods:
            if 'synchronized' in method.modifiers:
                synchronized_methods.append(method.name)
        if len(synchronized_methods) > 1:
            print(f"Detected!!![Synchronized Method Anti-Pattern] In file '{filename}', "
                  f"class '{class_name}' has multiple synchronized methods: {synchronized_methods}")

            message = (f"Detected!!![Synchronized Method Anti-Pattern] In file '{filename}', "
             f"class '{class_name}' has multiple synchronized methods: {synchronized_methods}")
            recommendation = (f"Recommendation: Consider using fine-grained synchronization to reduce contention. Instead of synchronizing the entire methods: {synchronized_methods}, synchronize only the critical section of the code that accesses shared resources. This can help reduce contention and improve performance.")
            # save this message to output.txt file
            with open('output.txt', 'a') as f:
                f.write(message)
                f.write('\n')
                f.write(recommendation)
                f.write('\n')
                f.write('\n')
                f.write('\n')
  
def detect_nested_locks(tree, filename):
    """Detect methods with nested synchronized blocks."""
    for _, method in tree.filter(javalang.tree.MethodDeclaration):
        method_name = method.name
        has_nested_synchronization = False
        sync_depth = [0]  # Use a list to allow modification within nested function

        def traverse(node):
            if isinstance(node, javalang.tree.SynchronizedStatement):
                sync_depth[0] += 1
                if sync_depth[0] > 1:
                    return True  # Nested synchronized block found
                # Traverse the statements inside the synchronized block
                if isinstance(node.block, list):
                    for child in node.block:
                        if traverse(child):
                            return True
                else:
                    for child in node.block.statements:
                        if traverse(child):
                            return True
                sync_depth[0] -= 1
            elif isinstance(node, javalang.tree.Node):
                for child in node.children:
                    if isinstance(child, javalang.tree.Node):
                        if traverse(child):
                            return True
                    elif isinstance(child, list):
                        for item in child:
                            if isinstance(item, javalang.tree.Node):
                                if traverse(item):
                                    return True
            return False

        if method.body:
            for statement in method.body:
                if traverse(statement):
                    has_nested_synchronization = True
                    break

        if has_nested_synchronization:
            print(f"Detected !!!![Nested Locks] In file '{filename}', method '{method_name}' has nested synchronized blocks.")
            # save it to a message variable
            message = (f"Detected !!!![Nested Locks] In file '{filename}', method '{method_name}' has nested synchronized blocks.")
            recommendation = (f"Recommendation: Lock Ordering or re-entrant locks should be employed which means that all threads must adhere to a standardized sequence of lock acquisition for the shared resources they need")
            # append it to the output.txt file
            with open('output.txt', 'a') as f:
                f.write(message)
                f.write('\n')
                f.write(recommendation)
                f.write('\n')
                f.write('\n')
                f.write('\n')

def detect_overly_split_locks(tree, filename):
    """Detect methods with multiple synchronized blocks locking the same object."""
    for _, method in tree.filter(javalang.tree.MethodDeclaration):
        method_name = method.name
        lock_usage = {}  # Dictionary to track locks and their occurrences

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
            # save it to a message variable
            message = (f"Detected !!! [Overly Split Locks] In file '{filename}', method '{method_name}' has multiple synchronized blocks locking the same object(s): {overly_split_locks}")
            recommendation = (f"Recommendation: Merging the split locks into more cohesive chunks")
            # append it to the output.txt file
            with open('output.txt', 'a') as f:
                f.write(message)
                f.write('\n')
                f.write(recommendation)
                f.write('\n')
                f.write('\n')
                f.write('\n')

def detect_reentrance_lockout(tree, filename):
    """Detect potential reentrance lockout issues."""
    # Step 1: Find declarations of locks (assume non-reentrant unless proven otherwise)
    lock_variables = set()
    for path, node in tree.filter(javalang.tree.VariableDeclarator):
        # Get the parent node from the path
        parent = path[-2] if len(path) >= 2 else None

        if parent and isinstance(parent, (javalang.tree.LocalVariableDeclaration, javalang.tree.FieldDeclaration)):
            var_type = parent.type.name
            if var_type == 'Lock' or var_type == 'ReadWriteLock':
                # Assume it's non-reentrant unless initialized to ReentrantLock
                initializer = node.initializer
                is_reentrant = False
                if initializer and isinstance(initializer, javalang.tree.ClassCreator):
                    lock_class = initializer.type.name
                    if lock_class in ['ReentrantLock', 'ReentrantReadWriteLock']:
                        is_reentrant = True
                if not is_reentrant:
                    lock_variables.add(node.name)

    # Step 2: Analyze methods for lock acquisition
    for _, method in tree.filter(javalang.tree.MethodDeclaration):
        method_name = method.name
        lock_stack = []
        def traverse(node):
            if isinstance(node, javalang.tree.MethodInvocation):
                method_call = node.member
                if method_call in ['lock', 'acquire']:
                    # Get the lock variable name
                    lock_name = None
                    if node.qualifier:
                        lock_name = node.qualifier
                    elif node.selectors:
                        if node.selectors[0].member:
                            lock_name = node.selectors[0].member
                    if lock_name in lock_variables:
                        if lock_name in lock_stack:
                            # Re-entrant lock acquisition detected
                            print(f"[Reentrance Lockout] In file '{filename}', method '{method_name}' may cause reentrance lockout on lock '{lock_name}'.")
                            # save it to a message variable
                            message = (f"[Reentrance Lockout] In file '{filename}', method '{method_name}' may cause reentrance lockout on lock '{lock_name}'.")
                            recommendation = (f"Recommendation: Ensure that the lock '{lock_name}' is reentrant or refactor the code to avoid reentrance lockout.By using a Reentrant Lock, you can avoid the lock contention issue that arises from using synchronized methods, allowing a thread to safely call inner() from outer() without deadlocking.")
                            # append it to the output.txt file
                            with open('output.txt', 'a') as f:
                                f.write(message)
                                f.write('\n')
                                f.write(recommendation)
                                f.write('\n')
                                f.write('\n')
                                f.write('\n')
                        else:
                            lock_stack.append(lock_name)
                elif method_call in ['unlock', 'release']:
                    # Remove lock from stack if present
                    lock_name = None
                    if node.qualifier:
                        lock_name = node.qualifier
                    elif node.selectors:
                        if node.selectors[0].member:
                            lock_name = node.selectors[0].member
                    if lock_name in lock_stack:
                        lock_stack.remove(lock_name)
            elif isinstance(node, javalang.tree.StatementExpression):
                # Handle expressions like lock.lock();
                expression = node.expression
                if isinstance(expression, javalang.tree.MethodInvocation):
                    traverse(expression)
            # Recurse into child nodes
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


def contains_loop(node):
    """Recursively check if a node or any of its descendants is a loop construct."""
    if node is None:
        return False

    if isinstance(node, list):
        for item in node:
            if contains_loop(item):
                return True
        return False  # Return False after checking all items

    print(f"Visiting node: {type(node).__name__}")
    
    if isinstance(node, (javalang.tree.ForStatement,
                         javalang.tree.WhileStatement,
                         javalang.tree.DoStatement)):
        print(f"Found loop: {type(node).__name__} at line {node.position}")
        return True
    
    elif isinstance(node, javalang.tree.BlockStatement):
        # For BlockStatement, iterate over its statements
        if node.statements:
            if contains_loop(node.statements):  # Pass the list of statements
                return True

    elif hasattr(node, 'children') and node.children:
        for child in node.children:
            if contains_loop(child):
                return True

    return False

def detect_loop_inside_critical(tree, filename):
    """Detect loops that are entirely within synchronized blocks or methods."""
    print(f"Analyzing file: {filename}")
    # Analyze synchronized methods
    for _, method in tree.filter(javalang.tree.MethodDeclaration):
        if 'synchronized' in method.modifiers:
            method_name = method.name
            print(f"Found synchronized method: {method_name}")
            # Check if the method body contains loops
            if method.body and contains_loop(method.body):
                # Anti-pattern detected
                message = (f"[Loop Inside Critical Section] In file '{filename}', synchronized method "
                           f"'{method_name}' contains a loop inside the synchronized context.")
                recommendation = ("Recommendation: Parallelization of the loop, breaking down the loop"
                                   "into smaller tasks which can be executed in parallel by distinct threads or processes ")
                print(message)
                # Append to output.txt
                with open('output.txt', 'a') as f:
                    f.write(message + '\n')
                    f.write(recommendation + '\n\n')
    # Analyze synchronized blocks
    for path, node in tree.filter(javalang.tree.SynchronizedStatement):
        print(f"Found synchronized block at line {node.position}")
        # Check if the synchronized block contains loops
        if contains_loop(node.block):
            # Get the parent method name if available
            method_name = None
            for ancestor in reversed(path):
                if isinstance(ancestor, javalang.tree.MethodDeclaration):
                    method_name = ancestor.name
                    break
            message = (f"[Loop Inside Critical Section] In file '{filename}', synchronized block "
                       f"contains a loop inside the synchronized context.")
            if method_name:
                message += f" (Method: {method_name})"
                recommendation = ("Recommendation: Parallelization of the loop, breaking down the loop"
                                   "into smaller tasks which can be executed in parallel by distinct threads or processes ")
                print(message)
            # Append to output.txt
            with open('output.txt', 'a') as f:
                f.write(message + '\n')
                f.write(recommendation + '\n\n')
        else:
            print("No loop found inside synchronized block")

def contains_synchronized_block(node):
    """Recursively check if a node or any of its descendants is a synchronized block."""
    if node is None:
        return False

    if isinstance(node, javalang.tree.SynchronizedStatement):
        print(f"Found synchronized block at line {node.position}")
        return True

    if isinstance(node, list):
        for item in node:
            if contains_synchronized_block(item):
                return True
        return False

    print(f"Visiting node: {type(node).__name__}")

    if hasattr(node, 'children'):
        for child in node.children:
            if contains_synchronized_block(child):
                return True
    return False

def detect_loop_outside_critical(tree, filename):
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
                print(f"Found loop: {loop_type} at line {node.position}")
                # Check if the loop body contains a synchronized block
                if contains_synchronized_block(node.body):
                    # Anti-pattern detected
                    message = (f"[Loop Outside Critical Section] In file '{filename}', method '{method_name}' "
                               f"contains a loop ({loop_type}) with a synchronized block inside.")
                    recommendation = ("Recommendation: Consider moving the synchronized block outside the loop if possible "
                                      "or minimizing the synchronized operations to reduce lock contention.")
                    print(message)
                    # Append to output.txt
                    with open('output.txt', 'a') as f:
                        f.write(message + '\n')
                        f.write(recommendation + '\n\n')
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

def detect_unified_locking(tree, filename):
    """Detect the Unified Locking anti-pattern where a single lock is used for multiple unrelated resources."""
    print(f"Analyzing file: {filename}")

    # Collect information about synchronized blocks
    lock_usage = {}  # Maps lock names to a set of resources they protect

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
        resources = get_modified_resources(sync_block.block)
        if lock_name:
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
            recommendation = ("Recommendation: Use ReentrantLock to manage shared resources by"
                               "ensuring that only one thread can execute critical sections at a time.")
            print(message)
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


def detect_same_lock(tree, filename):
    """Detect the Same Lock anti-pattern where multiple critical sections synchronize using the same mutable object."""
    print(f"Analyzing file: {filename}")

    # Collect information about synchronized blocks
    lock_usage = {}  # Maps lock names to a list of methods where it's used

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
            lock_usage[lock_name].add(method_name)

    # Identify locks used in multiple methods
    for lock_name, methods in lock_usage.items():
        if len(methods) > 1:
            # Anti-pattern detected
            methods_list = ', '.join(methods)
            message = (f"Detected!! [Same Lock] In file '{filename}', the lock '{lock_name}' (a mutable field) is used in multiple methods "
                       f"({methods_list}) for synchronization, which may lead to contention and thread safety issues.")
            recommendation = ("Recommendation: Implement Atomic type instead of object-based"
                               "synchronization")
            print(message)
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

def main(input_folder):
    """Main function to process Java files and detect anti-patterns."""
    java_files = find_java_files(input_folder)
    if not java_files:
        print(f"No Java files found in '{input_folder}'.")
    else:
        print(f"Found {len(java_files)} Java files.")
    for java_file in java_files:
        print(f"Processing file: {java_file}")
        try:
            with open(java_file, 'r', encoding='utf-8') as f:
                code = f.read()
            tree = javalang.parse.parse(code)
            detect_coarse_grained_synchronization(tree, java_file)
            detect_nested_locks(tree, java_file)
            detect_overly_split_locks(tree, java_file)
            detect_reentrance_lockout(tree, java_file)
            detect_loop_inside_critical(tree, java_file)
            detect_loop_outside_critical(tree, java_file)
            detect_unified_locking(tree,java_file)
            detect_same_lock(tree,java_file)
        except Exception as e:
            print(f"Failed to parse '{java_file}': {e}")
            traceback.print_exc()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python static_analysis_tool.py <input_folder>")
    else:
        input_folder = sys.argv[1]
        main(input_folder)
