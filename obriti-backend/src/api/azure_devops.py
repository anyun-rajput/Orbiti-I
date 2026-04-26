from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional
from api.scan import get_current_user, require_permission
from services.azure_devops import list_users, create_work_item, AzureDevOpsConfigError


router = APIRouter(dependencies=[Depends(require_permission("integrations"))])


@router.get("/azuredevops/users")
def azure_list_users(search: Optional[str] = Query(None)):
    try:
        return {"users": list_users(search)}
    except AzureDevOpsConfigError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:  # pragma: no cover - pass-through error
        raise HTTPException(status_code=502, detail=f"Azure DevOps error: {e}")


@router.post("/azuredevops/workitems")
def azure_create_work_item(
    title: str = Query(..., description="Work item title"),
    description: str = Query("", description="Markdown description"),
    assigned_to: Optional[str] = Query(None, description="User principal name or email"),
    type: str = Query("Issue", description="Work item type (Issue/Bug/Task)")
):
    try:
        created = create_work_item(title=title, description_markdown=description, assigned_to=assigned_to, work_item_type=type)
        return created
    except AzureDevOpsConfigError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:  # pragma: no cover - pass-through error
        raise HTTPException(status_code=502, detail=f"Azure DevOps error: {e}")


