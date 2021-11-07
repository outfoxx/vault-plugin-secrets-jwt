package jwtsecrets

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"path"
)

const (
	keyStorageRolePath = "role"
	keyRoleName        = "name"
	keySubject         = "subject"
	keyOtherClaims     = "claims"
)

type jwtSecretsRoleEntry struct {
	Subject     string                 `json:"subject"`
	OtherClaims map[string]interface{} `json:"claims"`
}

// Return response data for a role
func (r *jwtSecretsRoleEntry) toResponseData() map[string]interface{} {
	respData := map[string]interface{}{
		keySubject:     r.Subject,
		keyOtherClaims: r.OtherClaims,
	}
	return respData
}

func pathRole(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex(keyRoleName),
			Fields: map[string]*framework.FieldSchema{
				keyRoleName: {
					Type:        framework.TypeLowerCaseString,
					Description: "Specifies the name of the role to create. This is part of the request URL.",
					Required:    true,
				},
				keySubject: {
					Type:        framework.TypeString,
					Description: "Value of the subject claim (sub) of generated tokens. Subject is required and must match configured subject_pattern.",
				},
				keyOtherClaims: {
					Type:        framework.TypeMap,
					Description: "Values of other allowed claims. Only configured allowed_claims may be provided.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRolesRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRolesDelete,
				},
			},
			ExistenceCheck: b.pathRoleExistenceCheck,
			HelpSynopsis:    pathRoleHelpSyn,
			HelpDescription: pathRoleHelpDesc,
		},
		{
			Pattern: "roles/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRolesList,
				},
			},
			HelpSynopsis:    pathRoleListHelpSyn,
			HelpDescription: pathRoleListHelpDesc,
		},
	}
}

func (b *backend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	name := d.Get("name").(string)

	role, err := req.Storage.Get(ctx, path.Join(keyStorageRolePath, name))
	if err != nil {
		return false, err
	}

	return role != nil, nil
}

// pathRolesList makes a request to Vault storage to retrieve a list of roles for the backend
func (b *backend) pathRolesList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, keyStorageRolePath + "/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

// pathRolesRead makes a request to Vault storage to read a role and return response data
func (b *backend) pathRolesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := b.getRole(ctx, req.Storage, d.Get(keyRoleName).(string))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: entry.toResponseData(),
	}, nil
}

// pathRolesWrite makes a request to Vault storage to update a role based on the attributes passed to the role configuration
func (b *backend) pathRolesWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name, ok := d.GetOk(keyRoleName)
	if !ok {
		return logical.ErrorResponse("missing role name"), nil
	}

	roleEntry, err := b.getRole(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}

	if roleEntry == nil {
		roleEntry = &jwtSecretsRoleEntry{}
	}

	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	createOperation := req.Operation == logical.CreateOperation

	if subject, ok := d.GetOk(keySubject); ok {
		roleEntry.Subject = subject.(string)
	} else if !ok && createOperation {
		return nil, fmt.Errorf("missing subject in role")
	}

	if !config.SubjectPattern.MatchString(roleEntry.Subject) {
		return logical.ErrorResponse("validation of 'sub' claim failed"), logical.ErrInvalidRequest
	}

	if otherClaims, ok := d.GetOk(keyOtherClaims); ok {
		roleEntry.OtherClaims = otherClaims.(map[string]interface{})
	}

	if _, ok := roleEntry.OtherClaims["sub"]; ok {
		return logical.ErrorResponse("'sub' claim cannot be present in `claims` field"), logical.ErrInvalidRequest
	}

	for otherClaim := range roleEntry.OtherClaims {
		if allowedClaim, ok := config.allowedClaimsMap[otherClaim]; !ok || !allowedClaim {
			return logical.ErrorResponse("claim %s not permitted", otherClaim), logical.ErrInvalidRequest
		}
	}

	if rawAud, ok := roleEntry.OtherClaims["aud"]; ok {
		switch aud := rawAud.(type) {
		case string:
			if !config.AudiencePattern.MatchString(aud) {
				return logical.ErrorResponse("validation of 'aud' claim failed"), logical.ErrInvalidRequest
			}
		case []string:
			if config.MaxAudiences > -1 && len(aud) > config.MaxAudiences {
				return logical.ErrorResponse("too many audience claims: %d", len(aud)), logical.ErrInvalidRequest
			}
			for _, audEntry := range aud {
				if !config.AudiencePattern.MatchString(audEntry) {
					return logical.ErrorResponse("validation of 'aud' claim failed"), logical.ErrInvalidRequest
				}
			}
		default:
			return logical.ErrorResponse("'aud' claim was %T, not string or []string", rawAud), logical.ErrInvalidRequest
		}
	}

	if err := b.setRole(ctx, req.Storage, name.(string), roleEntry); err != nil {
		return nil, err
	}

	return nil, nil
}

// pathRolesDelete makes a request to Vault storage to delete a role
func (b *backend) pathRolesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, path.Join(keyStorageRolePath, d.Get(keyRoleName).(string)))
	if err != nil {
		return nil, fmt.Errorf("error deleting role: %w", err)
	}
	return nil, nil
}

// getRole gets the role from the Vault storage API
func (b *backend) getRole(ctx context.Context, stg logical.Storage, name string) (*jwtSecretsRoleEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("missing role name")
	}

	entry, err := stg.Get(ctx, path.Join(keyStorageRolePath, name))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var role jwtSecretsRoleEntry

	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}
	return &role, nil
}

// setRole adds the role to the Vault storage API
func (b *backend)setRole(ctx context.Context, stg logical.Storage, name string, roleEntry *jwtSecretsRoleEntry) error {
	entry, err := logical.StorageEntryJSON(path.Join(keyStorageRolePath, name), roleEntry)
	if err != nil {
		return err
	}

	if entry == nil {
		return fmt.Errorf("failed to create storage entry for role")
	}

	if err := stg.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

const pathRoleHelpSyn = `
Manages Vault role for generating tokens.
`

const pathRoleHelpDesc = `
Manages Vault role for generating tokens.

subject:          Subject claim (sub) for tokens generated using this role.
`

const pathRoleListHelpSyn = `
This endpoint returns a list of available roles.
`

const pathRoleListHelpDesc = `
This endpoint returns a list of available roles. Only the role names are returned, not any values.
`
