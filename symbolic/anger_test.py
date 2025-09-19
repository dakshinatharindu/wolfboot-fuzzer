import angr
import networkx as nx
import matplotlib.pyplot as plt
from collections import defaultdict
import pickle
import os

class CDFGAnalyzer:
    def __init__(self, binary_path):
        """Initialize the analyzer with a binary file."""
        self.binary_path = binary_path
        self.project = angr.Project(binary_path, auto_load_libs=False)
        self.cfg = None
        self.covered_blocks = set()
        self.coverage_data = defaultdict(int)
        
    def generate_cdfg(self, function_name=None):
        """Generate Control Data Flow Graph of the binary."""
        print(f"Generating CDFG for {self.binary_path}")
        
        # Generate CFG (Control Flow Graph)
        # For more accurate analysis, use CFGFast for speed or CFGEmulated for precision
        self.cfg = self.project.analyses.CFGFast(
            normalize=True,
            resolve_indirect_jumps=True,
            force_complete_scan=False
        )
        
        print(f"CFG generated with {len(self.cfg.nodes())} nodes")
        
        # If analyzing a specific function
        if function_name:
            func = self.project.kb.functions.get(function_name)
            if func:
                print(f"Analyzing function: {function_name} at {hex(func.addr)}")
                return self.get_function_graph(func)
        
        return self.cfg
    
    def get_function_graph(self, function):
        """Get the CFG for a specific function."""
        func_graph = function.transition_graph
        return func_graph
    
    def visualize_cdfg(self, output_file="cdfg.png", function_name=None):
        """Visualize the CDFG."""
        if not self.cfg:
            print("No CFG generated yet. Run generate_cdfg() first.")
            return
        
        # Create a networkx graph for visualization
        G = nx.DiGraph()
        
        if function_name:
            func = self.project.kb.functions.get(function_name)
            if func:
                graph = func.transition_graph
                for node in graph.nodes():
                    G.add_node(hex(node.addr))
                for src, dst in graph.edges():
                    G.add_edge(hex(src.addr), hex(dst.addr))
        else:
            # Add all nodes and edges from CFG
            for node in self.cfg.nodes():
                G.add_node(hex(node.addr))
            for src, dst in self.cfg.edges():
                G.add_edge(hex(src.addr), hex(dst.addr))
        
        # Plot the graph
        plt.figure(figsize=(12, 8))
        pos = nx.spring_layout(G, k=1, iterations=50)
        
        # Color nodes based on coverage
        node_colors = []
        for node in G.nodes():
            addr = int(node, 16)
            if addr in self.covered_blocks:
                node_colors.append('lightgreen')  # Covered
            else:
                node_colors.append('lightcoral')  # Not covered
        
        nx.draw(G, pos, node_color=node_colors, node_size=300, 
                with_labels=True, font_size=8, arrows=True)
        plt.title("Control Flow Graph (Green=Covered, Red=Uncovered)")
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"CDFG visualization saved to {output_file}")
    
    def run_symbolic_execution(self, input_data=None, max_steps=1000):
        """Run symbolic execution to explore paths and gather coverage."""
        print("Starting symbolic execution...")
        
        # Create initial state
        if input_data:
            # If we have specific input data
            initial_state = self.project.factory.entry_state(stdin=input_data)
        else:
            # Default symbolic input
            initial_state = self.project.factory.entry_state()
        
        # Create simulation manager
        simgr = self.project.factory.simulation_manager(initial_state)
        
        # Run symbolic execution
        step_count = 0
        while simgr.active and step_count < max_steps:
            simgr.step()
            step_count += 1
            
            # Track coverage for all active states
            for state in simgr.active:
                self.covered_blocks.add(state.addr)
                self.coverage_data[state.addr] += 1
            
            # Also track deadended states
            for state in simgr.deadended:
                self.covered_blocks.add(state.addr)
                self.coverage_data[state.addr] += 1
        
        print(f"Symbolic execution completed. Steps: {step_count}")
        print(f"Covered blocks: {len(self.covered_blocks)}")
        return simgr
    
    def calculate_coverage(self):
        """Calculate coverage percentage of the CDFG."""
        if not self.cfg:
            print("No CFG available. Generate CDFG first.")
            return 0
        
        total_blocks = len(self.cfg.nodes())
        covered_blocks = len(self.covered_blocks)
        
        if total_blocks == 0:
            return 0
        
        coverage_percentage = (covered_blocks / total_blocks) * 100
        print(f"Coverage: {covered_blocks}/{total_blocks} blocks ({coverage_percentage:.2f}%)")
        return coverage_percentage
    
    def get_uncovered_blocks(self):
        """Get list of uncovered blocks."""
        if not self.cfg:
            return []
        
        all_blocks = set(node.addr for node in self.cfg.nodes())
        uncovered = all_blocks - self.covered_blocks
        return list(uncovered)
    
    def generate_test_cases(self, target_blocks=None, max_cases=10):
        """Generate test cases to improve coverage."""
        print("Generating test cases based on coverage...")
        
        test_cases = []
        uncovered_blocks = self.get_uncovered_blocks()
        
        if not uncovered_blocks:
            print("All blocks are covered!")
            return test_cases
        
        # Target specific blocks or all uncovered blocks
        targets = target_blocks if target_blocks else uncovered_blocks[:max_cases]
        
        for target_addr in targets:
            print(f"Generating test case for block at {hex(target_addr)}")
            
            # Create initial state
            initial_state = self.project.factory.entry_state()
            
            # Create simulation manager
            simgr = self.project.factory.simulation_manager(initial_state)
            
            # Try to find a path to the target block
            try:
                simgr.explore(find=target_addr, num_find=1)
                
                if simgr.found:
                    # Extract the input that leads to this block
                    found_state = simgr.found[0]
                    
                    # Get concrete input values
                    if hasattr(found_state.posix, 'stdin'):
                        stdin_content = found_state.posix.stdin.load(0, found_state.posix.stdin.size)
                        try:
                            concrete_input = found_state.solver.eval(stdin_content, cast_to=bytes)
                            test_cases.append({
                                'target_block': hex(target_addr),
                                'input': concrete_input,
                                'input_hex': concrete_input.hex()
                            })
                            print(f"  Generated test case: {concrete_input.hex()}")
                        except:
                            print(f"  Could not concretize input for {hex(target_addr)}")
                    else:
                        # For cases without stdin, just record the path
                        test_cases.append({
                            'target_block': hex(target_addr),
                            'path_found': True
                        })
                        print(f"  Found path to {hex(target_addr)}")
                else:
                    print(f"  No path found to {hex(target_addr)}")
                    
            except Exception as e:
                print(f"  Error exploring to {hex(target_addr)}: {str(e)}")
        
        return test_cases
    
    def run_test_case(self, test_input):
        """Run a specific test case and update coverage."""
        print(f"Running test case: {test_input.hex() if isinstance(test_input, bytes) else test_input}")
        
        # Create state with the test input
        if isinstance(test_input, bytes):
            state = self.project.factory.entry_state(stdin=test_input)
        else:
            state = self.project.factory.entry_state()
        
        # Run the test
        simgr = self.project.factory.simulation_manager(state)
        simgr.run()
        
        # Update coverage
        new_coverage = set()
        for state in simgr.deadended + simgr.active:
            new_coverage.add(state.addr)
            self.covered_blocks.add(state.addr)
            self.coverage_data[state.addr] += 1
        
        print(f"Test case covered {len(new_coverage)} blocks")
        return new_coverage
    
    def save_coverage_data(self, filename="coverage_data.pkl"):
        """Save coverage data to file."""
        coverage_info = {
            'covered_blocks': self.covered_blocks,
            'coverage_data': dict(self.coverage_data),
            'binary_path': self.binary_path
        }
        
        with open(filename, 'wb') as f:
            pickle.dump(coverage_info, f)
        print(f"Coverage data saved to {filename}")
    
    def load_coverage_data(self, filename="coverage_data.pkl"):
        """Load coverage data from file."""
        if not os.path.exists(filename):
            print(f"Coverage file {filename} not found")
            return
        
        with open(filename, 'rb') as f:
            coverage_info = pickle.load(f)
        
        self.covered_blocks = coverage_info['covered_blocks']
        self.coverage_data = defaultdict(int, coverage_info['coverage_data'])
        print(f"Coverage data loaded from {filename}")
    
    def print_coverage_report(self):
        """Print a detailed coverage report."""
        if not self.cfg:
            print("No CFG available")
            return
        
        total_blocks = len(self.cfg.nodes())
        covered_blocks = len(self.covered_blocks)
        uncovered_blocks = self.get_uncovered_blocks()
        
        print("\n" + "="*50)
        print("COVERAGE REPORT")
        print("="*50)
        print(f"Total blocks: {total_blocks}")
        print(f"Covered blocks: {covered_blocks}")
        print(f"Uncovered blocks: {len(uncovered_blocks)}")
        print(f"Coverage percentage: {(covered_blocks/total_blocks)*100:.2f}%")
        
        if uncovered_blocks:
            print(f"\nUncovered blocks (showing first 10):")
            for addr in uncovered_blocks[:10]:
                print(f"  {hex(addr)}")
        
        print("\nMost executed blocks:")
        sorted_blocks = sorted(self.coverage_data.items(), key=lambda x: x[1], reverse=True)
        for addr, count in sorted_blocks[:10]:
            print(f"  {hex(addr)}: {count} times")


# Example usage
def main():
    # Replace with your binary path
    binary_path = "./wolfboot"
    
    # Initialize analyzer
    analyzer = CDFGAnalyzer(binary_path)
    
    # Step 1: Generate CDFG
    print("Step 1: Generating CDFG...")
    analyzer.generate_cdfg()
    
    # Step 2: Run initial symbolic execution
    print("\nStep 2: Running symbolic execution...")
    analyzer.run_symbolic_execution(max_steps=500)
    
    # Calculate initial coverage
    initial_coverage = analyzer.calculate_coverage()
    
    # Step 3: Generate test cases for uncovered blocks
    print("\nStep 3: Generating test cases...")
    test_cases = analyzer.generate_test_cases(max_cases=5)
    
    # Run generated test cases
    print("\nRunning generated test cases...")
    for test_case in test_cases:
        if 'input' in test_case:
            analyzer.run_test_case(test_case['input'])
    
    # Calculate final coverage
    final_coverage = analyzer.calculate_coverage()
    
    # Generate visualization
    analyzer.visualize_cdfg("coverage_visualization.png")
    
    # Print detailed report
    analyzer.print_coverage_report()
    
    # Save coverage data
    analyzer.save_coverage_data()
    
    print(f"\nCoverage improved from {initial_coverage:.2f}% to {final_coverage:.2f}%")


if __name__ == "__main__":
    main()