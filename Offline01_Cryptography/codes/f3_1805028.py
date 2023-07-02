from tabulate import tabulate

data = [
    ["k", "p", "g", "a or b", "A or B", "shared key"],
    [128, 2.245968, 0.0, 0.0, 0.0, 0.0],
    [192, 3.284521, 0.0, 0.0, 0.0, 0.0],
    [256, 18.773237, 0.0, 0.0, 0.0, 0.0]
]

# Print the data as a table with the "pretty" format
table = tabulate(data, headers="firstrow", tablefmt="fancy_grid")
print(table)