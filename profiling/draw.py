import matplotlib.pyplot as plt
import numpy as np

# 定义X值和两组Y值
x_values = np.array([4, 16, 64, 256, 1024, 2048, 8192, 32768, 131072])
y_values = np.array([11.87, 15.41, 22.88, 59.71, 206.67, 431.35, 1571.8, 6352.11, 24839.47])
pin_mem_values = np.array([1.57, 4.15, 11.24, 46.47, 189.33, 407.92, 1507.67, 6125.78, 24122.34])
map_sgtable_values = np.array([0.4, 0.43, 0.46, 0.51, 0.63, 0.64, 0.74, 3.48, 4.67])
nic_part_values = np.array([9.9, 10.83, 11.18, 12.73, 16.71, 22.79, 63.39, 222.85, 712.46])

# 创建图形和轴
fig, ax = plt.subplots()

# 绘制两条线，分别为y_values和pin_mem_values
ax.plot(x_values, y_values, marker='o', color='red', label='Total Time')
ax.plot(x_values, pin_mem_values, marker='x', color='#1E90FF', label='Pin Memory')
ax.plot(x_values, map_sgtable_values, marker='v', color='orange',label='Map Sgtable')
ax.plot(x_values, nic_part_values, marker='D', color='gray', label='NIC Part')

# 设置X轴和Y轴为对数刻度
ax.set_xscale('log', base=2)
ax.set_yscale('log', base=10)

# 设置轴标签
ax.set_xlabel('Memory Region Size (KiB)')
ax.set_ylabel('Time (us)')

# 设置图形的标题
ax.set_title('Registration Time Break Down')

# 显示网格
ax.grid(True)

# 显示图例
ax.legend()

# 显示图形
plt.show()

# 保存图形
plt.savefig("register_time.png")