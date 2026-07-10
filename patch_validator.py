import sys

path = '/opt/khepra/pkg/stig/validator.go'
with open(path, 'r') as fh:
    src = fh.read()

old_const = '\tFrameworkRHEL09STIG = "RHEL-09-STIG-V1R3"'
new_const = '\tFrameworkRHEL09STIG = "RHEL-09-STIG-V1R3"\n\tFrameworkRHEL10STIG = "RHEL-10-STIG-V1R1"'

old_case = '\tcase FrameworkRHEL09STIG:\n\t\terr = v.validateRHEL09STIG(result)'
new_case = '\tcase FrameworkRHEL09STIG:\n\t\terr = v.validateRHEL09STIG(result)\n\tcase FrameworkRHEL10STIG:\n\t\terr = v.validateRHEL10STIG(result)'

changed = 0

if old_const in src:
    src = src.replace(old_const, new_const, 1)
    changed += 1
    print('OK: constant inserted')
else:
    print('SKIP: constant already present or not found')

if old_case in src:
    src = src.replace(old_case, new_case, 1)
    changed += 1
    print('OK: case dispatch inserted')
else:
    print('SKIP: case already present or not found')

with open(path, 'w') as fh:
    fh.write(src)

print('Done. Changes applied:', changed)
