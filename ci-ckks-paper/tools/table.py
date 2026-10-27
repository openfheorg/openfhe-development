# Parse RESULT lines (stdin) into a compact table.
import sys, re
rows=[]
for line in sys.stdin:
    if 'RESULT' not in line: continue
    d=dict(re.findall(r'(\w[\w+]*)=([^\s]+)', line))
    rows.append(d)
cols=['scheme','logN','budget','sc','dist','slots','log2Q','log2P','galoisKeys','warm_median_s','us_per_real_slot','prec_bits_min','rms_bits','peakRSS_GB','threads']
print('| '+' | '.join(cols)+' |'); print('|'+'---|'*len(cols))
for d in rows: print('| '+' | '.join(d.get(c,'') for c in cols)+' |')
