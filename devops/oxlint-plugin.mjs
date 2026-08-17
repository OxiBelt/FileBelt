// SPDX-License-Identifier: Apache-2.0
// Adapted from OxiBelt commit 9daacf938a7d79fd618c18904435510eecb2f4c3 under Apache-2.0.

const RuleMeta = (Description) => ({
  type: "suggestion",
  docs: { description: Description },
  schema: [],
});

const IsPascalCase = (Name) =>
  Name.length === 0 || (Name[0] === Name[0].toUpperCase() && !Name.includes("_"));

const IsHookName = (Name) => /^use[A-Z][A-Za-z0-9]*$/u.test(Name);

const ReportName = (Context, Node, { AllowHook = false } = {}) => {
  const Name =
    Node?.type === "Identifier" || Node?.type === "PrivateIdentifier"
      ? Node.name
      : typeof Node?.value === "string"
        ? Node.value
        : undefined;

  if (Name !== undefined && !(AllowHook && IsHookName(Name)) && !IsPascalCase(Name)) {
    Context.report({
      node: Node,
      message: `Identifier '${Name}' must be in PascalCase`,
    });
  }
};

const CheckBinding = (Context, Pattern, { AllowHook = false } = {}) => {
  if (!Pattern) return;

  switch (Pattern.type) {
    case "Identifier":
      ReportName(Context, Pattern, { AllowHook });
      break;
    case "AssignmentPattern":
      CheckBinding(Context, Pattern.left, { AllowHook });
      break;
    case "ArrayPattern":
      for (const Element of Pattern.elements) CheckBinding(Context, Element, { AllowHook });
      break;
    case "ObjectPattern":
      for (const Property of Pattern.properties) {
        if (Property.type === "RestElement")
          CheckBinding(Context, Property.argument, { AllowHook });
        else CheckBinding(Context, Property.value, { AllowHook });
      }
      break;
    case "RestElement":
      CheckBinding(Context, Pattern.argument, { AllowHook });
      break;
    case "TSParameterProperty":
      CheckBinding(Context, Pattern.parameter, { AllowHook });
      break;
  }
};

const CheckProperty = (Context, Node) => {
  if (!Node.computed) ReportName(Context, Node.key);
};

const CheckFunction = (Context, Node) => {
  ReportName(Context, Node.id, { AllowHook: true });
  for (const Parameter of Node.params) {
    if (Parameter.type !== "TSParameterProperty") CheckBinding(Context, Parameter);
  }
};

const CheckTypeLike = (Context, Node) => ReportName(Context, Node.id);

const PascalCaseRule = {
  meta: RuleMeta("Require PascalCase for FileBelt declaration names"),
  create(Context) {
    return {
      VariableDeclarator(Node) {
        CheckBinding(Context, Node.id, { AllowHook: Node.id.type === "Identifier" });
      },
      CatchClause(Node) {
        CheckBinding(Context, Node.param);
      },
      FunctionDeclaration(Node) {
        CheckFunction(Context, Node);
      },
      FunctionExpression(Node) {
        CheckFunction(Context, Node);
      },
      TSDeclareFunction(Node) {
        CheckFunction(Context, Node);
      },
      TSEmptyBodyFunctionExpression(Node) {
        CheckFunction(Context, Node);
      },
      ArrowFunctionExpression(Node) {
        for (const Parameter of Node.params) CheckBinding(Context, Parameter);
      },
      ClassDeclaration(Node) {
        CheckTypeLike(Context, Node);
      },
      ClassExpression(Node) {
        CheckTypeLike(Context, Node);
      },
      TSInterfaceDeclaration(Node) {
        CheckTypeLike(Context, Node);
      },
      TSTypeAliasDeclaration(Node) {
        CheckTypeLike(Context, Node);
      },
      TSEnumDeclaration(Node) {
        CheckTypeLike(Context, Node);
      },
      TSTypeParameter(Node) {
        ReportName(Context, Node.name);
      },
      PropertyDefinition(Node) {
        CheckProperty(Context, Node);
      },
      TSAbstractPropertyDefinition(Node) {
        CheckProperty(Context, Node);
      },
      TSParameterProperty(Node) {
        CheckBinding(Context, Node.parameter);
      },
      TSPropertySignature(Node) {
        CheckProperty(Context, Node);
      },
    };
  },
};

export default {
  meta: { name: "filebelt" },
  rules: {
    "pascal-case": PascalCaseRule,
  },
};
