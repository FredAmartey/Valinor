import { CreateDepartmentForm } from "@/components/departments/create-department-form"

export default function NewDepartmentPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Create Department</h1>
        <p className="mt-1 text-sm text-zinc-500">Add a new department to your organization.</p>
      </div>
      <CreateDepartmentForm />
    </div>
  )
}
