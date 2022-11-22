package go_jwt_auth

import (
	"fmt"
	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v3"
)

func enforce(sub string, obj string, act string, adapter *gormadapter.Adapter) (bool, error) {
	//Load model configuration file and policy store adapter
	enforcer, err := casbin.NewEnforcer("config/rbac_model.conf", adapter)
	if err != nil {
		fmt.Println(err.Error())
		return false, fmt.Errorf("failed to create casbin enforcer: %w", err)
	}

	if err := enforcer.LoadPolicy(); err != nil {
		fmt.Println(err.Error())
		return false, fmt.Errorf("failed to load policy from DB: %w", err)
	}

	ok, err := enforcer.Enforce(sub, obj, act)
	return ok, err
}
