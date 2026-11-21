// Who may approve a gated change. Evaluated with Cedar (cedarpy).
//
// principal: Approver::"<name>"     attrs: environments (Set<String>)
// action:    Action::"approve"
// resource:  Environment::"<name>"  attrs: tier
// context:   requester, max_severity (0 none, 1 LOW .. 4 CRITICAL),
//            change_count, destroy_count, expired
//
// The gate also rejects HIGH/CRITICAL findings before approval is ever
// considered; the forbid on max_severity is defence in depth.

permit (
  principal is Approver,
  action == Action::"approve",
  resource is Environment
)
when { principal.environments.contains(resource.name) };

// Separation of duties: nobody approves their own change.
forbid (principal, action == Action::"approve", resource)
when { principal.name == context.requester };

forbid (principal, action == Action::"approve", resource)
when { context.max_severity >= 3 };

forbid (principal, action == Action::"approve", resource)
when { context.expired };
