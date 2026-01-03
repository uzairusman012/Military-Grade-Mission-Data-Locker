# ===================== ROLE BASED ACCESS =====================

PERMISSIONS = {
    "Commander": {"encrypt" : True, "decrypt" : True, "delete" : True},
    "Pilot": {"encrypt" : False, "decrypt" : True, "delete" : False},
    "Analyst": {"encrypt" : False, "decrypt" : True, "delete" : False},
    "Technician": {"encrypt" : False, "decrypt" : False, "delete" : False},
}

# verify permission

def check_permission(role, action):
    
    if PERMISSIONS.get(role, {}).get(action, False):
        return True
    
    print(f"Access Denied! {role} cannot {action} files.")
    return False

