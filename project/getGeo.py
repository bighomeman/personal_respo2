#!/usr/bin/python
# -*- coding: utf-8 -*-
import csv
import check_XForce as xf
import time

start = time.time()
with open(r'.\data\new.csv','r') as f:
    reader = csv.reader(f)
    rows = [row[0] for row in reader][1:]

xfdata = xf.start(1,rows)

with open(r'.\data\dataes.csv','wb') as f:
    fieldnames =['ip', 'geo', 'cats', 'score', 'asns', 'company']
    w =csv.DictWriter(f, fieldnames=fieldnames)
    w.writeheader()
    for i in range(len(xfdata)):
        xfdata.values()[i]['ip'] = xfdata.keys()[i]
        w.writerow(xfdata.values()[i])
end = time.time()
print(end-start)


