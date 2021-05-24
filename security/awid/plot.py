#!/usr/bin/env ipython

import matplotlib.pyplot as plt
import numpy as np
import json
import re

plt.figure(figsize=(16, 9))
plt.rcParams["font.family"] = "Times New Roman"

benchmark_string = """
run benchmark for HW_BREAKPOINT_LEN_0 with num: 4
delta time: 1.28679896 s
run benchmark for HW_BREAKPOINT_LEN_0 with num: 3
delta time: 1.28636667 s
run benchmark for HW_BREAKPOINT_LEN_0 with num: 2
delta time: 1.28627292 s
run benchmark for HW_BREAKPOINT_LEN_0 with num: 1
delta time: 1.28628854 s
run benchmark for HW_BREAKPOINT_LEN_0 with num: 0
delta time: 1.28618437 s
run benchmark for HW_BREAKPOINT_LEN_1 with num: 4
delta time: 1.28630000 s
run benchmark for HW_BREAKPOINT_LEN_1 with num: 3
delta time: 1.28645885 s
run benchmark for HW_BREAKPOINT_LEN_1 with num: 2
delta time: 1.28628490 s
run benchmark for HW_BREAKPOINT_LEN_1 with num: 1
delta time: 1.28631823 s
run benchmark for HW_BREAKPOINT_LEN_1 with num: 0
delta time: 1.28622656 s
run benchmark for HW_BREAKPOINT_LEN_2 with num: 4
delta time: 1.28630729 s
run benchmark for HW_BREAKPOINT_LEN_2 with num: 3
delta time: 1.28622656 s
run benchmark for HW_BREAKPOINT_LEN_2 with num: 2
delta time: 1.28629375 s
run benchmark for HW_BREAKPOINT_LEN_2 with num: 1
delta time: 1.28631302 s
run benchmark for HW_BREAKPOINT_LEN_2 with num: 0
delta time: 1.28623177 s
run benchmark for HW_BREAKPOINT_LEN_3 with num: 4
delta time: 1.28631771 s
run benchmark for HW_BREAKPOINT_LEN_3 with num: 3
delta time: 1.28630625 s
run benchmark for HW_BREAKPOINT_LEN_3 with num: 2
delta time: 1.28636354 s
run benchmark for HW_BREAKPOINT_LEN_3 with num: 1
delta time: 1.28641719 s
run benchmark for HW_BREAKPOINT_LEN_3 with num: 0
delta time: 1.28623177 s
run benchmark for HW_BREAKPOINT_LEN_4 with num: 4
delta time: 1.28628594 s
run benchmark for HW_BREAKPOINT_LEN_4 with num: 3
delta time: 1.28647135 s
run benchmark for HW_BREAKPOINT_LEN_4 with num: 2
delta time: 1.28628802 s
run benchmark for HW_BREAKPOINT_LEN_4 with num: 1
delta time: 1.28623854 s
run benchmark for HW_BREAKPOINT_LEN_4 with num: 0
delta time: 1.28619323 s
run benchmark for HW_BREAKPOINT_LEN_5 with num: 4
delta time: 1.28639635 s
run benchmark for HW_BREAKPOINT_LEN_5 with num: 3
delta time: 1.28616667 s
run benchmark for HW_BREAKPOINT_LEN_5 with num: 2
delta time: 1.28622813 s
run benchmark for HW_BREAKPOINT_LEN_5 with num: 1
delta time: 1.28632396 s
run benchmark for HW_BREAKPOINT_LEN_5 with num: 0
delta time: 1.28635104 s
run benchmark for HW_BREAKPOINT_LEN_6 with num: 4
delta time: 1.28625260 s
run benchmark for HW_BREAKPOINT_LEN_6 with num: 3
delta time: 1.28635937 s
run benchmark for HW_BREAKPOINT_LEN_6 with num: 2
delta time: 1.28620052 s
run benchmark for HW_BREAKPOINT_LEN_6 with num: 1
delta time: 1.28637187 s
run benchmark for HW_BREAKPOINT_LEN_6 with num: 0
delta time: 1.28610208 s
run benchmark for HW_BREAKPOINT_LEN_7 with num: 4
delta time: 1.28634010 s
run benchmark for HW_BREAKPOINT_LEN_7 with num: 3
delta time: 1.28626667 s
run benchmark for HW_BREAKPOINT_LEN_7 with num: 2
delta time: 1.28624792 s
run benchmark for HW_BREAKPOINT_LEN_7 with num: 1
delta time: 1.28630677 s
run benchmark for HW_BREAKPOINT_LEN_7 with num: 0
delta time: 1.28614531 s
run benchmark for HW_BREAKPOINT_LEN_8 with num: 4
delta time: 1.28625052 s
run benchmark for HW_BREAKPOINT_LEN_8 with num: 3
delta time: 1.28620625 s
run benchmark for HW_BREAKPOINT_LEN_8 with num: 2
delta time: 1.28623854 s
run benchmark for HW_BREAKPOINT_LEN_8 with num: 1
delta time: 1.28628490 s
run benchmark for HW_BREAKPOINT_LEN_8 with num: 0
delta time: 1.28634063 s
run benchmark for HW_BREAKPOINT_LEN_0 with num: 4
delta time: 43.09748541 s
run benchmark for HW_BREAKPOINT_LEN_0 with num: 3
delta time: 43.09692291 s
run benchmark for HW_BREAKPOINT_LEN_0 with num: 2
delta time: 43.09544114 s
run benchmark for HW_BREAKPOINT_LEN_0 with num: 1
delta time: 43.09591510 s
run benchmark for HW_BREAKPOINT_LEN_0 with num: 0
delta time: 43.09682239 s
run benchmark for HW_BREAKPOINT_LEN_1 with num: 4
delta time: 43.10661614 s
run benchmark for HW_BREAKPOINT_LEN_1 with num: 3
delta time: 43.11414791 s
run benchmark for HW_BREAKPOINT_LEN_1 with num: 2
delta time: 43.11807083 s
run benchmark for HW_BREAKPOINT_LEN_1 with num: 1
delta time: 43.11141041 s
run benchmark for HW_BREAKPOINT_LEN_1 with num: 0
delta time: 43.10064062 s
run benchmark for HW_BREAKPOINT_LEN_2 with num: 4
delta time: 43.11167187 s
run benchmark for HW_BREAKPOINT_LEN_2 with num: 3
delta time: 43.11623176 s
run benchmark for HW_BREAKPOINT_LEN_2 with num: 2
delta time: 43.11744374 s
run benchmark for HW_BREAKPOINT_LEN_2 with num: 1
delta time: 43.11158697 s
run benchmark for HW_BREAKPOINT_LEN_2 with num: 0
delta time: 43.09899374 s
run benchmark for HW_BREAKPOINT_LEN_3 with num: 4
delta time: 43.11905728 s
run benchmark for HW_BREAKPOINT_LEN_3 with num: 3
delta time: 43.11009166 s
run benchmark for HW_BREAKPOINT_LEN_3 with num: 2
delta time: 43.11229114 s
run benchmark for HW_BREAKPOINT_LEN_3 with num: 1
delta time: 43.11138072 s
run benchmark for HW_BREAKPOINT_LEN_3 with num: 0
delta time: 43.10260260 s
run benchmark for HW_BREAKPOINT_LEN_4 with num: 4
delta time: 43.10990260 s
run benchmark for HW_BREAKPOINT_LEN_4 with num: 3
delta time: 43.11617187 s
run benchmark for HW_BREAKPOINT_LEN_4 with num: 2
delta time: 43.11199739 s
run benchmark for HW_BREAKPOINT_LEN_4 with num: 1
delta time: 43.11043541 s
run benchmark for HW_BREAKPOINT_LEN_4 with num: 0
delta time: 43.09920885 s
run benchmark for HW_BREAKPOINT_LEN_5 with num: 4
delta time: 43.11484218 s
run benchmark for HW_BREAKPOINT_LEN_5 with num: 3
delta time: 43.11454166 s
run benchmark for HW_BREAKPOINT_LEN_5 with num: 2
delta time: 43.11153489 s
run benchmark for HW_BREAKPOINT_LEN_5 with num: 1
delta time: 43.11701353 s
run benchmark for HW_BREAKPOINT_LEN_5 with num: 0
delta time: 43.10206249 s
run benchmark for HW_BREAKPOINT_LEN_6 with num: 4
delta time: 43.11235676 s
run benchmark for HW_BREAKPOINT_LEN_6 with num: 3
delta time: 43.11287708 s
run benchmark for HW_BREAKPOINT_LEN_6 with num: 2
delta time: 43.10999791 s
run benchmark for HW_BREAKPOINT_LEN_6 with num: 1
delta time: 43.11266874 s
run benchmark for HW_BREAKPOINT_LEN_6 with num: 0
delta time: 43.09726666 s
run benchmark for HW_BREAKPOINT_LEN_7 with num: 4
delta time: 43.10890989 s
run benchmark for HW_BREAKPOINT_LEN_7 with num: 3
delta time: 43.10596145 s
run benchmark for HW_BREAKPOINT_LEN_7 with num: 2
delta time: 43.10296926 s
run benchmark for HW_BREAKPOINT_LEN_7 with num: 1
delta time: 43.09936354 s
run benchmark for HW_BREAKPOINT_LEN_7 with num: 0
delta time: 43.09155312 s
run benchmark for HW_BREAKPOINT_LEN_8 with num: 4
delta time: 43.10232187 s
run benchmark for HW_BREAKPOINT_LEN_8 with num: 3
delta time: 43.10515416 s
run benchmark for HW_BREAKPOINT_LEN_8 with num: 2
delta time: 43.10827291 s
run benchmark for HW_BREAKPOINT_LEN_8 with num: 1
delta time: 43.11017135 s
run benchmark for HW_BREAKPOINT_LEN_8 with num: 0
delta time: 43.09357343 s
"""

benchmark_list = benchmark_string.strip("\n").split("\n")
benchmark_result = [[benchmark_list[2*i], benchmark_list[2*i+1]]
                    for i in range(int(len(benchmark_list)/2))]

len_re = re.compile("LEN_(\d)")
num_re = re.compile("num: (\d)")
time_re = re.compile("\d+.\d+")
benchmark_dict = {}
for result in benchmark_result:
    hwp_len = len_re.search(result[0]).group(1)
    hwp_num = num_re.search(result[0]).group(1)
    hwp_time = float(time_re.search(result[1]).group())
    if hwp_len == 0:
        continue
    if hwp_time < 2:
        benchmark_dict[(hwp_len, hwp_num, "serial")] = hwp_time
    else:
        benchmark_dict[(hwp_len, hwp_num, "random")] = hwp_time


def plot(rw_type: str):
    xlabels = []
    xticks = []
    yticks = []
    for key, time in benchmark_dict.items():
        hwp_len = int(key[0])
        hwp_num = int(key[1])
        hwp_type = key[2]
        if hwp_type == rw_type:
            xticks.append(hwp_num * 16 + hwp_len)
            yticks.append(time)
            if hwp_len == 4:
                xlabels.append("hwp_num={0}\nhwp_len=1-8".format(hwp_num))
            else:
                xlabels.append("")

    # location = np.arange(len(x_labels))
    plt.bar(xticks, yticks, tick_label=xlabels,
            alpha=0.8, color="w", edgecolor="k")
    # plt.legend(loc=1)
    plt.title(rw_type.title() + " Read Write")
    if rw_type == "serial":
        plt.ylim([0, 2])
    else:
        plt.ylim([42, 44])
    plt.show()
