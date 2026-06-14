package souhimbou

import "testing"

func TestAuthorize(t *testing.T) {
	admin := &User{Email: "admin@test.com", Role: RoleAdmin}
	operator := &User{Email: "op@test.com", Role: RoleOperator}
	viewer := &User{Email: "view@test.com", Role: RoleViewer}

	adminCmd := &Command{Action: "delete_db", RequiredRole: RoleAdmin}
	opCmd := &Command{Action: "restart_service", RequiredRole: RoleOperator}
	viewCmd := &Command{Action: "read_logs", RequiredRole: RoleViewer}

	tests := []struct {
		name    string
		user    *User
		cmd     *Command
		wantErr bool
	}{
		{"Admin can do Admin", admin, adminCmd, false},
		{"Admin can do Op", admin, opCmd, false},
		{"Op can do Op", operator, opCmd, false},
		{"Op can do View", operator, viewCmd, false},
		{"Viewer can do View", viewer, viewCmd, false},
		{"Viewer cannot do Op", viewer, opCmd, true},
		{"Viewer cannot do Admin", viewer, adminCmd, true},
		{"Op cannot do Admin", operator, adminCmd, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Authorize(tt.user, tt.cmd)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authorize() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
