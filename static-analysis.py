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
            print(f"Detected!!![Coarse-Grained Anti-Pattern] In file '{filename}', "
                  f"class '{class_name}' has multiple synchronized methods: {synchronized_methods}")

            message = (f"Detected!!![Coarse-Grained Anti-Pattern] In file '{filename}', "
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

def detect_wrong_lock_usage(tree, filename):
    """Detect potential wrong lock usage on shared variables."""
    # Step 1: Identify class fields (potential shared variables)
    shared_variables = set()
    for _, field_decl in tree.filter(javalang.tree.FieldDeclaration):
        for declarator in field_decl.declarators:
            shared_variables.add(declarator.name)

    print(f"Shared variables: {shared_variables}")

    # Step 2: Analyze methods for variable accesses
    for _, method in tree.filter(javalang.tree.MethodDeclaration):
        method_name = method.name
        accesses = []

        def traverse(node, in_synchronized=False, lock_name=None):
            if isinstance(node, javalang.tree.SynchronizedStatement):
                # Dynamically access the lock attribute
                lock_expr = getattr(node, 'lock', None) or getattr(node, 'monitor', None) or getattr(node, 'expression', None)

                if lock_expr is None:
                    print(f"Could not find lock expression in SynchronizedStatement at line {node.position.line}")
                    return

                lock_str = None

                # Get the lock expression as a string
                if isinstance(lock_expr, javalang.tree.Literal):
                    lock_str = lock_expr.value
                elif isinstance(lock_expr, javalang.tree.MemberReference):
                    lock_str = lock_expr.member
                elif isinstance(lock_expr, javalang.tree.This):
                    lock_str = 'this'
                elif isinstance(lock_expr, javalang.tree.Identifier):
                    lock_str = lock_expr.name
                else:
                    lock_str = str(lock_expr)

                # Traverse the block with updated context
                if node.block and hasattr(node.block, 'statements'):
                    for stmt in node.block.statements:
                        traverse(stmt, in_synchronized=True, lock_name=lock_str)
            elif isinstance(node, javalang.tree.StatementExpression):
                expression = node.expression
                traverse(expression, in_synchronized, lock_name)
            elif isinstance(node, (javalang.tree.Assignment, javalang.tree.MemberReference,
                                   javalang.tree.PostIncrement, javalang.tree.PreIncrement,
                                   javalang.tree.PostDecrement, javalang.tree.PreDecrement)):
                # Variable access
                var_name = None
                if isinstance(node, javalang.tree.Assignment):
                    if isinstance(node.expressionl, javalang.tree.MemberReference):
                        var_name = node.expressionl.member
                    elif isinstance(node.expressionl, javalang.tree.Identifier):
                        var_name = node.expressionl.name
                elif isinstance(node, javalang.tree.MemberReference):
                    var_name = node.member
                elif isinstance(node, (javalang.tree.PostIncrement, javalang.tree.PreIncrement,
                                       javalang.tree.PostDecrement, javalang.tree.PreDecrement)):
                    if isinstance(node.expression, javalang.tree.MemberReference):
                        var_name = node.expression.member
                    elif isinstance(node.expression, javalang.tree.Identifier):
                        var_name = node.expression.name

                if var_name in shared_variables:
                    print(f"Variable '{var_name}' accessed in method '{method_name}', "
                          f"in_synchronized={in_synchronized}, lock_name={lock_name}")
                    accesses.append({
                        'variable': var_name,
                        'in_synchronized': in_synchronized,
                        'lock_name': lock_name
                    })
            elif isinstance(node, javalang.tree.MethodInvocation):
                # Potential access through method calls
                pass  # Simplification: Ignored for this analysis

            # Recurse into child nodes
            for child in node.children:
                if isinstance(child, javalang.tree.Node):
                    traverse(child, in_synchronized, lock_name)
                elif isinstance(child, list):
                    for item in child:
                        if isinstance(item, javalang.tree.Node):
                            traverse(item, in_synchronized, lock_name)

        if method.body:
            for statement in method.body:
                traverse(statement)

        print(f"Accesses in method '{method_name}': {accesses}")

        # Analyze accesses for inconsistent locking
        for var in shared_variables:
            locks_used = set()
            for access in accesses:
                if access['variable'] == var:
                    if access['in_synchronized']:
                        locks_used.add(access['lock_name'])
                    else:
                        locks_used.add(None)
            if len(locks_used) > 1:
                print(f"[Wrong Lock] In file '{filename}', variable '{var}' is accessed with inconsistent locking in method '{method_name}'. Locks used: {locks_used}")
                recommendation = (f"Recommendation: We need to ensure that all threads use the same lock when accessing the shared variable. This can be achieved by synchronizing the method or block of code that accesses the shared variable using the same lock object.")
                # append it to the output.txt file
                with open('output.txt', 'a') as f:
                    f.write(message)
                    f.write('\n')
                    f.write(recommendation)
                    f.write('\n')
                    f.write('\n')
                    f.write('\n')

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
            #detect_wrong_lock_usage(tree, java_file)
        except Exception as e:
            print(f"Failed to parse '{java_file}': {e}")
            traceback.print_exc()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python static_analysis_tool.py <input_folder>")
    else:
        input_folder = sys.argv[1]
        main(input_folder)
