import matplotlib.pyplot as plt

# Latency values in milliseconds
operations = ['INSERT', 'UPDATE', 'DELETE', 'QUERY']
latency_with_ebpf = [1.1720, 1.2338, 1.2062, 0.33706]  
latency_without_ebpf = [1.1410, 1.2014, 1.1550, 0.3175] 

x = range(len(operations))

# Create the plot
fig, ax = plt.subplots()

# Plotting the values
ax.bar(x, latency_with_ebpf, width=0.4, label='With eBPF', align='center')
ax.bar(x, latency_without_ebpf, width=0.4, label='Without eBPF', align='edge')

# Adding labels and title
ax.set_xlabel('Operation')
ax.set_ylabel('Latency (ms)')
ax.set_title('PostgreSQL Latency Comparison with and without eBPF')
ax.set_xticks(x)
ax.set_xticklabels(operations)
ax.legend()

# Display the plot
plt.tight_layout()
plt.show()
